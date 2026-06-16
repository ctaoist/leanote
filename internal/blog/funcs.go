// Package blog is the public-blog rendering engine. It renders a user's active
// theme (Go html/template files on disk) into HTML for the dynamic blog routes,
// the owner preview, and the static-site generator. Markdown post bodies are
// rendered client-side by the theme (markdown-it), so the server only emits the
// raw Content — which keeps the static export self-contained.
//
// The template funcs and ViewArgs contract mirror the legacy leanote/Revel blog
// (app/init.go funcmap + revel template_functions.go) so existing themes render
// unmodified.
package blog

import (
	"encoding/json"
	"fmt"
	"html"
	"html/template"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// localeKey is the ViewArgs key holding the current locale (revel's
// CurrentLocaleViewArg). blogTags/msg read it; we default it to "zh".
const localeKey = "currentLocale"

// colorTags are the four reserved tag names leanote renders as colored labels.
var colorTags = map[string]bool{"red": true, "blue": true, "yellow": true, "green": true}

// FuncMap returns the template funcs leanote themes rely on: the custom funcs
// from app/init.go plus the revel built-ins (set, raw, nl2br, ...) that themes
// commonly call. Go's html/template already provides eq/ne/lt/gt/and/or/not/
// index/len/printf, so those are intentionally absent here.
func FuncMap() template.FuncMap {
	return template.FuncMap{
		// ----- revel built-ins used by themes -----
		"set": func(viewArgs map[string]any, key string, value any) string {
			viewArgs[key] = value
			return ""
		},
		"append": func(viewArgs map[string]any, key string, value any) string {
			if viewArgs[key] == nil {
				viewArgs[key] = []any{value}
			} else if arr, ok := viewArgs[key].([]any); ok {
				viewArgs[key] = append(arr, value)
			}
			return ""
		},
		"firstof": func(args ...any) any {
			for _, v := range args {
				switch x := v.(type) {
				case nil:
					continue
				case string:
					if x == "" {
						continue
					}
					return x
				default:
					return v
				}
			}
			return nil
		},
		"nl2br": func(text string) template.HTML {
			return template.HTML(strings.Replace(template.HTMLEscapeString(text), "\n", "<br>", -1))
		},
		"pad": func(str string, width int) template.HTML {
			if len(str) >= width {
				return template.HTML(html.EscapeString(str))
			}
			return template.HTML(html.EscapeString(str) + strings.Repeat("&nbsp;", width-len(str)))
		},
		"pluralize": func(items any, overrides ...string) string {
			singular, plural := "", "s"
			if len(overrides) >= 1 {
				singular = overrides[0]
			}
			if len(overrides) >= 2 {
				plural = overrides[1]
			}
			switch v := reflect.ValueOf(items); v.Kind() {
			case reflect.Int, reflect.Int64:
				if v.Int() != 1 {
					return plural
				}
			case reflect.Slice, reflect.Array:
				if v.Len() != 1 {
					return plural
				}
			}
			return singular
		},
		"date":    func(t time.Time) string { return t.Format("2006-01-02") },
		"slug":    slug,
		"even":    func(a int) bool { return a%2 == 0 },
		"timeago": timeAgo,

		// ----- leanote custom funcs (app/init.go) -----
		"raw": func(s string) template.HTML { return template.HTML(s) },
		"trim": func(s string) string {
			s = strings.Trim(s, " ")
			s = strings.Trim(s, "\n")
			s = strings.Trim(s, "&nbsp;")
			return strings.TrimSpace(s)
		},
		"add":  func(i int) string { return fmt.Sprintf("%v", i+1) },
		"sub":  func(i int) int { return i - 1 },
		"incr": func(n, i int) int { return n + i },
		"join": func(arr []string) template.HTML {
			if arr == nil {
				return template.HTML("")
			}
			return template.HTML(strings.Join(arr, ","))
		},
		"concat":    func(s1, s2 string) template.HTML { return template.HTML(s1 + s2) },
		"concatStr": func(strs ...string) string { return strings.Join(strs, "") },
		"decodeUrlValue": func(i string) string {
			v, _ := url.ParseQuery("a=" + i)
			return v.Get("a")
		},
		"json": func(i any) string {
			b, _ := json.Marshal(i)
			return string(b)
		},
		"jsonJs": func(i any) template.JS {
			b, _ := json.Marshal(i)
			return template.JS(string(b))
		},
		"datetime": func(t time.Time) template.HTML {
			return template.HTML(t.Format("2006-01-02 15:04:05"))
		},
		"dateFormat": func(t time.Time, format string) template.HTML {
			return template.HTML(t.Format(format))
		},
		"unixDatetime": func(unixSec string) template.HTML {
			sec, _ := strconv.Atoi(unixSec)
			return template.HTML(time.Unix(int64(sec), 0).Format("2006-01-02 15:04:05"))
		},
		"has": func(i any, key string) bool {
			t := reflect.TypeOf(i)
			if t == nil || t.Kind() != reflect.Struct {
				return false
			}
			_, ok := t.FieldByName(key)
			return ok
		},
		"li":      func(string) string { return "" },
		"urlCond": func(string, any, any) template.HTML { return "" },
		"blogTags": func(viewArgs map[string]any, tags []string) template.HTML {
			tagPostUrl, _ := viewArgs["tagPostsUrl"].(string)
			return blogTagsHTML(tags, tagPostUrl)
		},
		"blogTagsForExport": func(_ map[string]any, tags []string) template.HTML {
			return blogTagsExportHTML(tags)
		},
		"blogTagsLea": func(_ map[string]any, tags []string, _ string) template.HTML {
			return blogTagsExportHTML(tags)
		},
		// No i18n message files here: msg/leaMsg/rawMsg are passthroughs.
		"msg": func(_ map[string]any, message string, args ...any) template.HTML {
			if len(args) > 0 {
				return template.HTML(fmt.Sprintf(message, args...))
			}
			return template.HTML(message)
		},
		"leaMsg":  func(_ map[string]any, key string) template.HTML { return template.HTML(key) },
		"rawMsg":  func(_ map[string]any, message string, _ ...any) template.JS { return template.JS(message) },
		"urlConcat": urlConcat,
		"sorterTh":  sorterTh,
		"page":      page,
		"N":         nRange,
	}
}

func blogTagsHTML(tags []string, tagPostUrl string) template.HTML {
	if len(tags) == 0 {
		return ""
	}
	var b strings.Builder
	for i, tag := range tags {
		if tag == "" {
			continue
		}
		classes := "label"
		if colorTags[tag] {
			classes += " label-" + tag
		} else {
			classes += " label-default"
		}
		classes += " label-post"
		b.WriteString(`<a class="` + classes + `" href="` + tagPostUrl + "/" + url.PathEscape(tag) + `">` + template.HTMLEscapeString(tag) + `</a>`)
		if i != len(tags)-1 {
			b.WriteString(" ")
		}
	}
	return template.HTML(b.String())
}

func blogTagsExportHTML(tags []string) template.HTML {
	if len(tags) == 0 {
		return ""
	}
	var b strings.Builder
	for i, tag := range tags {
		if tag == "" {
			continue
		}
		classes := "label"
		if colorTags[tag] {
			classes += " label-" + tag
		} else {
			classes += " label-default"
		}
		classes += " label-post"
		b.WriteString(`<span class="` + classes + `">` + template.HTMLEscapeString(tag) + `</span>`)
		if i != len(tags)-1 {
			b.WriteString(" ")
		}
	}
	return template.HTML(b.String())
}

// urlConcat appends key/value query pairs to url (leanote's app/init.go version).
func urlConcat(u string, v ...any) string {
	q := ""
	for i := 0; i+1 < len(v); i += 2 {
		key, _ := v[i].(string)
		valueStr := ""
		switch val := v[i+1].(type) {
		case string:
			valueStr = val
		case int:
			valueStr = strconv.Itoa(val)
		default:
			valueStr = fmt.Sprintf("%v", val)
		}
		if key == "" || valueStr == "" {
			continue
		}
		s := key + "=" + valueStr
		if q != "" {
			q += "&" + s
		} else {
			q = s
		}
	}
	if q == "" {
		return u
	}
	if strings.Contains(u, "?") {
		return u + "&" + q
	}
	return u + "?" + q
}

func sorterTh(u, sorterField string, sorterI any) template.HTMLAttr {
	sorter, _ := sorterI.(string)
	h := `data-url="` + u + `" data-sorter="` + sorterField + `"`
	h += ` class="th-sortable `
	if sorter == sorterField+"-up" {
		h += `th-sort-up"`
	} else if sorter == sorterField+"-down" {
		h += `th-sort-down"`
	} else {
		h += `"`
	}
	return template.HTMLAttr(h)
}

func page(urlBase string, page, pageSize, count int) template.HTML {
	if count == 0 {
		return ""
	}
	totalPage := (count + pageSize - 1) / pageSize
	preClass, nextClass := "", ""
	prePage := page - 1
	if prePage == 0 {
		prePage = 1
	}
	nextPage := page + 1
	preUrl := urlBase + "?page=" + strconv.Itoa(prePage)
	nextUrl := urlBase + "?page=" + strconv.Itoa(nextPage)
	if page == 1 {
		preClass = "disabled"
		preUrl = "#"
	}
	if totalPage <= page {
		nextClass = "disabled"
		nextUrl = "#"
	}
	return template.HTML("<li class='" + preClass + "'><a href='" + preUrl + "'>Previous</a></li> <li  class='" + nextClass + "'><a href='" + nextUrl + "'>Next</a></li>")
}

// nRange yields start..end inclusive over a channel ({{range $i := N 1 total}}).
func nRange(start, end int) chan int {
	stream := make(chan int)
	go func() {
		for i := start; i <= end; i++ {
			stream <- i
		}
		close(stream)
	}()
	return stream
}

// slug mirrors revel.Slug.
func slug(text string) string {
	text = strings.ToLower(text)
	var b strings.Builder
	for _, r := range text {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '-' || r == '_':
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

// timeAgo is a dependency-free relative-time formatter (themes that call
// {{timeago .Time}} get a coarse English string; most themes do this in JS).
func timeAgo(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return strconv.Itoa(int(d.Minutes())) + " minutes ago"
	case d < 24*time.Hour:
		return strconv.Itoa(int(d.Hours())) + " hours ago"
	case d < 30*24*time.Hour:
		return strconv.Itoa(int(d.Hours()/24)) + " days ago"
	case d < 365*24*time.Hour:
		return strconv.Itoa(int(d.Hours()/(24*30))) + " months ago"
	default:
		return strconv.Itoa(int(d.Hours()/(24*365))) + " years ago"
	}
}
