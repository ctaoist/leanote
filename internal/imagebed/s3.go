// Package imagebed signs S3-compatible object-storage requests for the optional
// "network image bed" mode. The backend never uploads bytes itself: in server
// sign mode it hands the browser a short-lived presigned PUT URL (this package),
// and in client sign mode the browser signs in-browser (see web-src/src/lib/s3.ts).
//
// SigV4 is implemented from scratch (stdlib only) so the server gains no new
// dependency and the self-test can independently recompute and assert the
// signature.
package imagebed

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// httpClient is used only for the LIST (browse) call. Uploads never touch the
// server: in server mode the browser PUTs to a presigned URL, in client mode it
// signs in-browser. Listing returns object keys (metadata), not image bytes.
var httpClient = &http.Client{Timeout: 15 * time.Second}

// S3Config is everything needed to address and sign against one bucket.
type S3Config struct {
	Endpoint      string // host[:port], no scheme, e.g. s3.amazonaws.com or 127.0.0.1:9000
	Region        string // e.g. us-east-1
	Bucket        string
	AccessKey     string
	SecretKey     string
	PublicBaseURL string // optional public base for composing the stored URL
	KeyPrefix     string // optional object-key prefix, e.g. "leanote/"
	UseSSL        bool
	PathStyle     bool // path-style (host/bucket/key) vs virtual-host (bucket.host/key)
}

// Bed is one configured image bed as stored (JSON) in the imageBeds config. The
// admin can configure several and pick one active. signMode is per-bed. JSON
// tags are camelCase to match the browser/admin wire shape.
type Bed struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	SignMode      string `json:"signMode"` // client | server
	Endpoint      string `json:"endpoint"`
	Region        string `json:"region"`
	Bucket        string `json:"bucket"`
	AccessKey     string `json:"accessKey"`
	SecretKey     string `json:"secretKey"`
	UseSSL        bool   `json:"useSSL"`
	PathStyle     bool   `json:"pathStyle"`
	PublicBaseURL string `json:"publicBaseURL"`
	KeyPrefix     string `json:"keyPrefix"`
}

// S3 projects a Bed onto the addressing/signing config.
func (b Bed) S3() S3Config {
	return S3Config{
		Endpoint:      b.Endpoint,
		Region:        b.Region,
		Bucket:        b.Bucket,
		AccessKey:     b.AccessKey,
		SecretKey:     b.SecretKey,
		PublicBaseURL: b.PublicBaseURL,
		KeyPrefix:     b.KeyPrefix,
		UseSSL:        b.UseSSL,
		PathStyle:     b.PathStyle,
	}
}

// Valid reports whether the minimum fields for signing are present.
func (c S3Config) Valid() bool {
	return c.endpointHost() != "" && c.Bucket != "" && c.AccessKey != "" && c.SecretKey != ""
}

func (c S3Config) region() string {
	if c.Region == "" {
		return "us-east-1"
	}
	return c.Region
}

func (c S3Config) scheme() string {
	if c.UseSSL {
		return "https"
	}
	return "http"
}

// endpointHost strips any scheme/trailing slash the admin may have pasted.
func (c S3Config) endpointHost() string {
	e := c.Endpoint
	e = strings.TrimPrefix(e, "https://")
	e = strings.TrimPrefix(e, "http://")
	return strings.TrimRight(e, "/")
}

// hostHeader is the Host used for both the request and the SigV4 host header.
func (c S3Config) hostHeader() string {
	if c.PathStyle {
		return c.endpointHost()
	}
	return c.Bucket + "." + c.endpointHost()
}

// canonicalURI is the request path: "/[bucket/]key" with each segment
// AWS-URI-encoded but slashes preserved.
func (c S3Config) canonicalURI(key string) string {
	p := "/"
	if c.PathStyle {
		p += awsURIEncode(c.Bucket, true) + "/"
	}
	return p + awsURIEncode(key, false)
}

// PublicURL is the URL stored in the note/markdown for an object.
func (c S3Config) PublicURL(key string) string {
	if c.PublicBaseURL != "" {
		return strings.TrimRight(c.PublicBaseURL, "/") + "/" + awsURIEncode(key, false)
	}
	return c.scheme() + "://" + c.hostHeader() + c.canonicalURI(key)
}

// BuildKey produces the object key for an upload. name is the desired path
// under the bed's KeyPrefix — typically just the original filename, or
// "album/filename" when an album (prefix) is chosen. The filename is preserved
// (per-segment sanitized); same name overwrites by design. An empty/extension-
// less name is filled in.
func (c S3Config) BuildKey(name string) string {
	return strings.TrimLeft(c.KeyPrefix, "/") + sanitizeKeyPath(name)
}

// sanitizeKeyPath keeps a relative object path safe: forward slashes preserved
// (so "album/photo.png" stays foldered), but empty/"."/".." segments dropped
// (no traversal) and control/separator chars scrubbed per segment. A missing
// extension on the final segment defaults to .png.
func sanitizeKeyPath(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	segs := strings.Split(p, "/")
	out := make([]string, 0, len(segs))
	for _, s := range segs {
		s = sanitizeSegment(s)
		if s == "" || s == "." || s == ".." {
			continue
		}
		out = append(out, s)
	}
	name := strings.Join(out, "/")
	if name == "" {
		name = "image-" + randomHex(8) + ".png"
	}
	last := name
	if i := strings.LastIndex(name, "/"); i >= 0 {
		last = name[i+1:]
	}
	if !strings.Contains(last, ".") {
		name += ".png"
	}
	return name
}

// sanitizeSegment trims a single path segment and drops control characters.
func sanitizeSegment(s string) string {
	s = strings.TrimSpace(s)
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

// bucketURI is the canonical request path for bucket-level operations (LIST):
// "/" for virtual-host style, "/bucket" for path-style.
func (c S3Config) bucketURI() string {
	if c.PathStyle {
		return "/" + awsURIEncode(c.Bucket, true)
	}
	return "/"
}

// PresignPut returns a presigned PUT URL (SigV4 query-string, UNSIGNED-PAYLOAD,
// only the host header signed) valid for expires. The browser PUTs the bytes
// directly to it.
func (c S3Config) PresignPut(key string, expires time.Duration) (string, error) {
	if !c.Valid() {
		return "", errors.New("incomplete s3 config")
	}
	return c.presign("PUT", key, expires, time.Now().UTC())
}

// PresignDelete returns a presigned DELETE URL valid for expires. Used by the
// admin "test connection" so a server-sign-mode bed can be tested with a plain
// browser fetch (no Web Crypto needed).
func (c S3Config) PresignDelete(key string, expires time.Duration) (string, error) {
	if !c.Valid() {
		return "", errors.New("incomplete s3 config")
	}
	return c.presign("DELETE", key, expires, time.Now().UTC())
}

// presign is the testable core (now is injected).
func (c S3Config) presign(method, key string, expires time.Duration, now time.Time) (string, error) {
	host := c.hostHeader()
	region := c.region()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")
	scope := dateStamp + "/" + region + "/s3/aws4_request"

	secs := int(expires.Seconds())
	if secs <= 0 {
		secs = 300
	}
	// Query params must be sorted by key; values URI-encoded (slashes encoded).
	params := map[string]string{
		"X-Amz-Algorithm":     "AWS4-HMAC-SHA256",
		"X-Amz-Credential":    c.AccessKey + "/" + scope,
		"X-Amz-Date":          amzDate,
		"X-Amz-Expires":       strconv.Itoa(secs),
		"X-Amz-SignedHeaders": "host",
	}
	canonicalQuery := encodeQuery(params)

	canonicalURI := c.canonicalURI(key)
	canonicalHeaders := "host:" + host + "\n"
	signedHeaders := "host"
	payloadHash := "UNSIGNED-PAYLOAD"

	canonicalRequest := strings.Join([]string{
		method, canonicalURI, canonicalQuery, canonicalHeaders, signedHeaders, payloadHash,
	}, "\n")

	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256", amzDate, scope, sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	signature := hex.EncodeToString(hmacSHA256(signingKey(c.SecretKey, dateStamp, region, "s3"), stringToSign))
	url := c.scheme() + "://" + host + canonicalURI + "?" + canonicalQuery + "&X-Amz-Signature=" + signature
	return url, nil
}

// ----- LIST (browse) -----

// ListObject is one object returned by a LIST.
type ListObject struct {
	Key  string
	Size int64
}

// ListResult is a parsed ListObjectsV2 page.
type ListResult struct {
	CommonPrefixes []string     // sub-"folders" (treated as albums)
	Objects        []ListObject // objects directly under the queried prefix
	NextToken      string       // continuation token when truncated
	IsTruncated    bool
}

// ListObjects performs a header-signed (SigV4) GET ListObjectsV2 against the
// bucket and parses the XML. delimiter "/" groups sub-prefixes into
// CommonPrefixes. maxKeys (when > 0) bounds the page size (max-keys). This is the
// only call the server makes to S3; it transfers object keys, never image bytes.
func (c S3Config) ListObjects(prefix, delimiter, token string, maxKeys int) (ListResult, error) {
	if !c.Valid() {
		return ListResult{}, errors.New("incomplete s3 config")
	}
	now := time.Now().UTC()
	host := c.hostHeader()
	region := c.region()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")
	scope := dateStamp + "/" + region + "/s3/aws4_request"

	params := map[string]string{"list-type": "2"}
	if prefix != "" {
		params["prefix"] = prefix
	}
	if delimiter != "" {
		params["delimiter"] = delimiter
	}
	if maxKeys > 0 {
		params["max-keys"] = strconv.Itoa(maxKeys)
	}
	if token != "" {
		params["continuation-token"] = token
	}
	canonicalQuery := encodeQuery(params)

	canonicalURI := c.bucketURI()
	payloadHash := sha256Hex([]byte("")) // empty GET body
	canonicalHeaders := "host:" + host + "\n" +
		"x-amz-content-sha256:" + payloadHash + "\n" +
		"x-amz-date:" + amzDate + "\n"
	signedHeaders := "host;x-amz-content-sha256;x-amz-date"
	canonicalRequest := strings.Join([]string{
		"GET", canonicalURI, canonicalQuery, canonicalHeaders, signedHeaders, payloadHash,
	}, "\n")
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256", amzDate, scope, sha256Hex([]byte(canonicalRequest)),
	}, "\n")
	signature := hex.EncodeToString(hmacSHA256(signingKey(c.SecretKey, dateStamp, region, "s3"), stringToSign))
	authorization := "AWS4-HMAC-SHA256 Credential=" + c.AccessKey + "/" + scope +
		", SignedHeaders=" + signedHeaders + ", Signature=" + signature

	reqURL := c.scheme() + "://" + host + canonicalURI + "?" + canonicalQuery
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return ListResult{}, err
	}
	req.Header.Set("x-amz-content-sha256", payloadHash)
	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("Authorization", authorization)

	resp, err := httpClient.Do(req)
	if err != nil {
		return ListResult{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != 200 {
		return ListResult{}, fmt.Errorf("list failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return parseListXML(body)
}

// listBucketResult mirrors the subset of the ListObjectsV2 XML we need.
type listBucketResult struct {
	XMLName               xml.Name `xml:"ListBucketResult"`
	IsTruncated           bool     `xml:"IsTruncated"`
	NextContinuationToken string   `xml:"NextContinuationToken"`
	Contents              []struct {
		Key  string `xml:"Key"`
		Size int64  `xml:"Size"`
	} `xml:"Contents"`
	CommonPrefixes []struct {
		Prefix string `xml:"Prefix"`
	} `xml:"CommonPrefixes"`
}

func parseListXML(b []byte) (ListResult, error) {
	var r listBucketResult
	if err := xml.Unmarshal(b, &r); err != nil {
		return ListResult{}, err
	}
	res := ListResult{NextToken: r.NextContinuationToken, IsTruncated: r.IsTruncated}
	for _, p := range r.CommonPrefixes {
		res.CommonPrefixes = append(res.CommonPrefixes, p.Prefix)
	}
	for _, o := range r.Contents {
		res.Objects = append(res.Objects, ListObject{Key: o.Key, Size: o.Size})
	}
	return res, nil
}

// ----- object management (delete / put-empty / copy) -----

// signedDo performs a header-SigV4-signed request used by the management ops
// (delete, create-placeholder, copy). canonicalURI is the object path; extra are
// additional headers that must be part of the signature (e.g. x-amz-copy-source).
func (c S3Config) signedDo(method, canonicalURI string, extra map[string]string, body []byte) (int, []byte, error) {
	now := time.Now().UTC()
	host := c.hostHeader()
	region := c.region()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")
	scope := dateStamp + "/" + region + "/s3/aws4_request"
	payloadHash := sha256Hex(body)

	headers := map[string]string{
		"host":                 host,
		"x-amz-content-sha256": payloadHash,
		"x-amz-date":           amzDate,
	}
	for k, v := range extra {
		headers[strings.ToLower(k)] = v
	}
	names := make([]string, 0, len(headers))
	for k := range headers {
		names = append(names, k)
	}
	sort.Strings(names)
	var ch strings.Builder
	for _, n := range names {
		ch.WriteString(n + ":" + headers[n] + "\n")
	}
	signedHeaders := strings.Join(names, ";")

	canonicalRequest := strings.Join([]string{method, canonicalURI, "", ch.String(), signedHeaders, payloadHash}, "\n")
	stringToSign := strings.Join([]string{"AWS4-HMAC-SHA256", amzDate, scope, sha256Hex([]byte(canonicalRequest))}, "\n")
	signature := hex.EncodeToString(hmacSHA256(signingKey(c.SecretKey, dateStamp, region, "s3"), stringToSign))
	authorization := "AWS4-HMAC-SHA256 Credential=" + c.AccessKey + "/" + scope +
		", SignedHeaders=" + signedHeaders + ", Signature=" + signature

	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, c.scheme()+"://"+host+canonicalURI, bodyReader)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("x-amz-content-sha256", payloadHash)
	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("Authorization", authorization)
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, rb, nil
}

// DeleteObject removes one object. 404 is treated as success (already gone).
func (c S3Config) DeleteObject(key string) error {
	if !c.Valid() {
		return errors.New("incomplete s3 config")
	}
	st, body, err := c.signedDo("DELETE", c.canonicalURI(key), nil, nil)
	if err != nil {
		return err
	}
	if st != 204 && st != 200 && st != 404 {
		return fmt.Errorf("delete failed (%d): %s", st, strings.TrimSpace(string(body)))
	}
	return nil
}

// PutEmpty creates a zero-byte object (used as an empty-album placeholder).
func (c S3Config) PutEmpty(key string) error {
	if !c.Valid() {
		return errors.New("incomplete s3 config")
	}
	st, body, err := c.signedDo("PUT", c.canonicalURI(key), nil, []byte{})
	if err != nil {
		return err
	}
	if st != 200 {
		return fmt.Errorf("put failed (%d): %s", st, strings.TrimSpace(string(body)))
	}
	return nil
}

// CopyObject server-side copies srcKey to dstKey (no bytes through us). Used by
// the album-rename loop alongside DeleteObject.
func (c S3Config) CopyObject(srcKey, dstKey string) error {
	if !c.Valid() {
		return errors.New("incomplete s3 config")
	}
	source := "/" + c.Bucket + "/" + awsURIEncode(srcKey, false)
	st, body, err := c.signedDo("PUT", c.canonicalURI(dstKey), map[string]string{"x-amz-copy-source": source}, []byte{})
	if err != nil {
		return err
	}
	if st != 200 {
		return fmt.Errorf("copy failed (%d): %s", st, strings.TrimSpace(string(body)))
	}
	return nil
}

// ContentType maps a (dotted, lowercase) image extension to a MIME type.
func ContentType(ext string) string {
	switch strings.ToLower(ext) {
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".gif":
		return "image/gif"
	case ".bmp":
		return "image/bmp"
	case ".webp":
		return "image/webp"
	case ".svg":
		return "image/svg+xml"
	default:
		return "image/png"
	}
}

// ----- SigV4 primitives -----

// encodeQuery builds a canonical, sorted, URI-encoded query string.
func encodeQuery(params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = awsURIEncode(k, true) + "=" + awsURIEncode(params[k], true)
	}
	return strings.Join(parts, "&")
}

// awsURIEncode percent-encodes per RFC 3986 / AWS rules, operating on UTF-8
// bytes. When encodeSlash is false, '/' is preserved (used for object paths).
func awsURIEncode(s string, encodeSlash bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') ||
			ch == '-' || ch == '_' || ch == '.' || ch == '~':
			b.WriteByte(ch)
		case ch == '/' && !encodeSlash:
			b.WriteByte(ch)
		default:
			fmt.Fprintf(&b, "%%%02X", ch)
		}
	}
	return b.String()
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func signingKey(secret, dateStamp, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), dateStamp)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	return hmacSHA256(kService, "aws4_request")
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
