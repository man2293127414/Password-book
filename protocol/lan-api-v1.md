# LAN API v1

LAN API v1 仅在用户从手机主动开启“PC 访问”后监听手机当前的局域网地址。它面向同一 Wi-Fi 或连接手机热点的一个个人可信 PC；服务停止、会话超时或网络发生变化后，本次 run 与会话都失效。

## 静态页面与本地依赖

- `GET /` 与 `GET /index.html` 返回同一份 `text/html; charset=utf-8` 页面。
- 其余静态路径必须逐项存在于 APK 内的 `web/runtime-assets.tsv`。该清单是相对路径到 MIME 的精确白名单；当前只允许页面 CSS、首方 `.mjs` 模块和随 APK 提交的 Noble `.js` 文件，分别使用 `text/css; charset=utf-8` 或 `text/javascript; charset=utf-8`。
- `runtime-assets.tsv` 自身、`vendor-manifest.json`、`package.json`、许可证文件、其他 Android assets、未知路径和路径穿越都不可通过 HTTP 读取。
- 静态路由只接受 `GET`。静态与 API 的成功、错误响应都包含 `Cache-Control: no-store` 和 `X-Content-Type-Options: nosniff`。

`index.html` 的 import map 将 `@noble/curves/`、`@noble/hashes/`、`@noble/ciphers/` 映射到 `/node_modules/@noble/.../`。浏览器只加载 APK 内固定版本的 ESM 文件，不访问 CDN、npm 或其他远端地址，也不在构建或运行时安装依赖。普通局域网地址使用 HTTP，因此页面不依赖仅限 secure context 的 `crypto.subtle`；P-256、HKDF-SHA-256 和 AES-256-GCM 由本地 Noble 模块完成。

## 配对

1. 浏览器请求 `GET /api/v1/pairing-info`。响应为 `{v,runId,serverPublicKey}`，其中二进制字段采用无填充 base64url。生产服务每次 run 生成 32 字节 `runId` 和临时 P-256 `serverPublicKey`。底层互操作向量允许使用非空 `runId`，现有已知答案向量使用 16 字节 HKDF salt；这不改变生产 pairing-info 的 32 字节约束。
2. 浏览器只在内存中生成临时 P-256 密钥对。用户输入手机显示的六位数字访问码后，浏览器以 ECDH 共享秘密和 `runId` 通过 HKDF-SHA-256 派生 handshake key，再用 AES-256-GCM 加密访问码。
3. 浏览器向 `POST /api/v1/pairing-submit` 提交 `{v,clientPublicKey,nonce,ciphertext}`。成功响应为 `{v,nonce,ciphertext}`；浏览器解密后才得到 `{sessionId}`，并派生方向分离的 client-to-server 与 server-to-client key。
4. 配对成功后浏览器立即发送 `snapshot`，再进入密码库页面。访问码输入会被清空，不进入 URL、日志、HTML 属性或持久化存储。

每次 run 最多允许五次错误访问码尝试；pairing 提交的最小间隔为 500 ms。服务只允许一个已连接客户端，连接建立后不再接受第二个客户端。访问码认证失败时页面显示“访问码错误或已失效”，不泄露剩余尝试次数；提交过快时显示“操作过快，请稍后重试”。

## 加密命令与请求顺序

全部密码库操作使用 `POST /api/v1/vault`，`Content-Type` 为 `application/json`，并要求存在且不超过 32 KiB 的 `Content-Length`。请求和响应的外层 envelope 均为 `{v,sessionId,counter,ciphertext}`；业务命令、结果与业务错误只存在于 AES-GCM 密文内。AAD 绑定 HTTP method、`/api/v1/vault`、`sessionId` 和 `counter`，响应使用独立的 server-to-client key 并回传同一 counter。

浏览器维护一个串行 Promise 队列。每个请求按入队顺序分配严格递增的 counter，任何刷新或 mutation 都不能绕过队列；客户端同时校验响应 counter，拒绝重放、未请求或篡改的响应。服务端在 AES-GCM 认证成功后、执行任何 mutation 前消耗 counter，只有成功的业务操作才刷新 30 分钟会话超时。已配对页面可低频请求公开的 `GET /api/v1/pairing-info` 比较本次 `runId` 和临时服务器公钥，以发现服务停止或 run 更换；该健康检查不发送 vault command、不分配 counter，也不刷新会话空闲时间。

协议定义以下十个 `op`：

- `snapshot`
- `credential.create`、`credential.update`、`credential.delete`
- `category.create`、`category.rename`、`category.delete`
- `tag.create`、`tag.rename`、`tag.delete`

`credential.create/update` 使用 `name`、`account`、`password`、`url`、`categoryId`、`tagIds`、`notes`；update/delete 以及分类、标签的 rename/delete 使用 `id` 和 `expectedVersion`。快照包含 `revision`、`credentials`、`categories`、`tags`；凭据包含 `id`、上述业务字段、`version`、`createdAt`、`updatedAt`。每次 mutation 成功后，浏览器统一重新请求 `snapshot` 再渲染，不在 PC 端复制手机业务层的关联更新规则。

## 错误、断开与页面数据

加密业务错误的页面处理如下：

- `VALIDATION`：保留表单内容并显示校验提示。
- `NOT_FOUND`：提示目标已不存在并刷新快照。
- `STALE_VERSION`：提示“记录已变化，请刷新后重试”，随后刷新快照，不自动覆盖手机上的新版本。
- `BAD_REQUEST`、`INTERNAL`：显示不含堆栈或敏感值的通用失败提示。

`UNAUTHORIZED`、`DISCONNECTED`、网络失败、解密或认证失败、响应重放都会使浏览器立即进入断开状态。服务停止、30 分钟超时、手机网络变化、手机执行导入或清空也会销毁本次 run 的 key。断开或 `pagehide` 时客户端停止排队请求，主动覆写其持有的密钥字节数组并释放引用，清除内存快照、表单、已显示密码和敏感 DOM；页面刷新后必须重新配对。JavaScript 不能保证浏览器垃圾回收的具体时刻，因此不承诺绝对即时擦除所有浏览器进程内存。

页面不使用 `localStorage`、`sessionStorage`、IndexedDB、Service Worker 或其他浏览器持久化，也不建立 PC 数据库。密码默认固定显示八个圆点 `••••••••`，仅在用户点击当前记录后逐条显示；复制账号或密码不要求先显示密码。复制优先使用浏览器剪贴板 API，在普通 HTTP 不可用或失败时使用一次性 textarea 与 `document.execCommand("copy")` 回退，并在 `finally` 中清空和移除临时字段。

浏览器地址虽然是 HTTP，访问码、账号、密码、备注和全部 vault command/response 仍由上述 ECDH + HKDF + AES-GCM 应用层协议保护，不以明文业务 JSON 发送。首版威胁模型仍假设个人可信 PC 与可信局域网；它不提供 HTTPS 服务器身份认证，也不防护能够主动替换手机页面或公钥的攻击者。
