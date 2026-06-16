// 生成 MongoDB 风格的 24 位十六进制 ObjectId（新建笔记/笔记本时由前端生成，
// 与 leanote/public/js/object_id.js 行为一致：4字节时间戳 + 5字节随机 + 3字节计数器）。

let counter = Math.floor(Math.random() * 0xffffff);

function randomHex(bytes: number): string {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return Array.from(arr, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function newObjectId(): string {
  const timestamp = Math.floor(Date.now() / 1000)
    .toString(16)
    .padStart(8, "0");
  const machineAndPid = randomHex(5); // 5 字节随机
  counter = (counter + 1) % 0xffffff;
  const counterHex = counter.toString(16).padStart(6, "0");
  return (timestamp + machineAndPid + counterHex).slice(0, 24);
}
