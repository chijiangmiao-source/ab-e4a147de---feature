# 稀疏 Merkle 根批量配置变更核验服务

中子源实验设备配置登记册的审查端：审查员粘贴**旧根 / 新根 / 旧叶→新叶 / 共享兄弟证明**，
服务**同时自底向上重建旧树和新树**，在不相信提交方摘要的前提下确认：新根只能由
「获准键的旧值被替换为新值」产生，并返回每层合并的左右摘要、默认空子树与双根复算轨迹。

纯 Python 标准库实现（无第三方运行时依赖）。

## 密码学约定

| 对象 | 编码 |
|---|---|
| 叶节点 | `SHA-256(0x00 ‖ 256 位叶摘要)` |
| 内部节点 | `SHA-256(0x01 ‖ 左摘要 ‖ 32 字节右摘要)` |
| 默认空子树 | `DEFAULT[0]=SHA-256("")`，`DEFAULT[h]=H(01‖D[h-1]‖D[h-1])` |

层级 `level` 从叶槽 256 降到根 0；兄弟证明以 `depth`（节点层级 1..256）与等长
`prefix`（0/1 前缀）定位，含义即「该 depth 与前缀处的子树根摘要」。

## 运行（Docker Compose，宿主机端口可配置）

```bash
cp .env.example .env
docker compose up --build
# 自定义宿主机端口：
APP_PORT=9090 docker compose up --build
```

- 页面：http://localhost:${APP_PORT:-8080}/
- 健康：http://localhost:${APP_PORT:-8080}/healthz
- API：`POST /api/verify`（无状态；每次结论带独立 `verification_id`，`Cache-Control: no-store`）

页面点「载入共享前缀双键示例」可获得真实数据；也可 `POST /api/demo` 取 JSON。

## 单次验收服务 `verify`

`docker compose up` 时 `verify` 容器会在 `web` 健康后**一次性**执行三阶段并退出：

1. **镜像构建检查**：校验镜像内文件布局、全模块字节码编译与导入；
   若容器内可达 Docker daemon 且提供 `/src` 构建上下文，则执行真实 `docker build`。
2. **代码测试**：围绕
   - 共享前缀的双键变更（双树重建、双根分别比对）
   - 被篡改的兄弟摘要（`old_root_mismatch`，带可定位 level）
   - 多余证明节点（路径外 / 与另一证明冗余 / 值为默认空树）
   以及缺少非默认兄弟、路径重复、路径次序错误、共享祖先冲突、单根独立错误等。
3. **HTTP 冒烟**：对真实 API（`http://web:8080`）执行健康、页面、双键通过、
   篡改拒绝、多余节点拒绝，并校验失败结论的 `verification_id` 与此前通过不同。

查看验收结果与退出码：

```bash
docker compose up --build --abort-on-container-exit --exit-code-from verify
echo $?     # 0 全部通过；非零即验收失败
```

`verify` 只运行一次即终止（`restart: "no"`），不会常驻；web 服务不受影响。

## 为什么不会「只分别检查两个根」或「旧结论伪装」

- 每个内部节点都在**同一次遍历**中为旧/新各算一次：共享兄弟在两棵树中是同一摘要，
  意味着「子树未变」；若该子树实际含变更叶，立即 `shared_ancestor_conflict`。
- 旧根、新根分别与各自重建根比较，任一不符即以独立错误码（`old_root_mismatch` /
  `new_root_mismatch`）拒绝并给出定位层级。
- 页面提交前清空结果区、按本次响应的 `verification_id` 渲染；服务端不保存任何历史结论。

## 本地开发（无需 Docker）

```bash
python3 app/server.py                 # 或 PORT=9090 ...
python3 -m unittest discover -s tests # 25 个代码测试
python3 tests/http_smoke.py --spawn   # 自起服务做 HTTP 冒烟
bash tests/run_verify.sh              # 等价于容器内 verify 的全流程
```

## 仓库结构

```
app/smt.py             稀疏树、双树重建、所有拒绝规则、参考建树/造证明
app/server.py          标准库 HTTP 服务（/、/healthz、/api/verify、/api/demo）
app/static/            审查页面（HTML/CSS/JS）
tests/test_smt.py      25 个代码测试
tests/http_smoke.py    真实 API 冒烟
tests/run_verify.sh    verify 单次服务的三阶段验收脚本
Dockerfile             python:3.11-slim，内置 HEALTHCHECK
docker-compose.yml     web（可配置宿主端口）+ verify（一次性，退出码验收）
```
