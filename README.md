# 稀疏 Merkle 根批量配置变更核验服务

中子源实验设备配置登记册的审查端：审查员粘贴**旧根 / 新根 / 旧叶→新叶 / 共享兄弟证明**，
服务**同时自底向上重建旧树和新树**，在不相信提交方摘要的前提下确认：新根只能由
「获准键的旧值被替换为新值」产生，并返回每层合并的左右摘要、默认空子树与双根复算轨迹。

审查员还可随批提交一组**前缀许可**（可选）：每项含唯一许可标识、0/1 前缀与可覆盖的
最多变更键数。服务在双根复算通过后，把每个变更键与其所有前缀匹配许可组成容量约束，
确认本次每个实际替换键都能被获准范围承接，并返回逐键命中前缀与各许可的已用/未用额度。

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

页面点「载入共享前缀双键示例」可获得真实数据（含一组嵌套/重叠前缀许可：提交后可见
较宽许可额度耗尽、较窄许可仍有剩余而核验通过）；点「容量不足变体」则只保留一条
quota=1 的宽许可，提交后真实 API 返回 `license_capacity` 拒绝。也可 `POST /api/demo` 取 JSON。

## 前缀许可（可选）

请求体可附带 `"licenses"` 数组，每项：

| 字段 | 含义 |
|---|---|
| `id` | 唯一许可标识（1..128 字符非空字符串，重复即拒绝） |
| `prefix` | 0/1 前缀（可带 `0b`，0..256 位；空前缀匹配所有键） |
| `quota` | 可覆盖的最多变更键数（正整数） |

语义与顺序保证：

- **先根后许可**：服务先完成原有旧/新根与共享证明的同步复算，**只有双根有效后**
  才把变更键与许可组成容量约束；根不符时许可错误不会掩盖根错误。
- **容量约束**：每个变更键必须恰好占用一个前缀匹配许可的额度，任何键无候选许可
  （`license_uncovered_key`）或全部键无法各占用一次额度（`license_capacity`）即整批拒绝。
- **非输入序贪心**：嵌套/重叠许可不按输入顺序分配；系统在全部可行分配中取
  **键路径升序 × 许可标识序列字典序最小**的唯一稳定见证（区间凸二部匹配 + 逐步可行性判定）。
- **见证返回**：`license_witness.assignments` 给出逐键命中许可与命中前缀，
  `license_witness.licenses` 给出每条许可的 `quota / used / unused`。
- **错误定位**：`duplicate_license_id`（标识重复）、`license_prefix_format`（前缀非法）、
  `license_quota`（额度非正整数）等均指明 `licenses[i]`；任何许可拒绝都不会把此前
  成功分配留作本次结论（每次结论带独立 `verification_id`）。
- **兼容**：不填 `licenses`（或为空数组）时，请求与响应与原有核验完全一致，
  响应不含 `license_witness` 字段。

## 单次验收服务 `verify`

`docker compose up` 时 `verify` 容器会在 `web` 健康后**一次性**执行三阶段并退出：

1. **镜像构建检查**：校验镜像内文件布局、全模块字节码编译与导入；
   若容器内可达 Docker daemon 且提供 `/src` 构建上下文，则执行真实 `docker build`。
2. **代码测试**：围绕
   - 共享前缀的双键变更（双树重建、双根分别比对）
   - 被篡改的兄弟摘要（`old_root_mismatch`，带可定位 level）
   - 多余证明节点（路径外 / 与另一证明冗余 / 值为默认空树）
   - 前缀许可（重叠许可的稳定字典序最小分配、宽许可耗尽窄许可可用仍通过、
     容量不足 / 键无候选 / 标识重复 / 前缀非法 / 额度非正的拒绝与兼容性）
   以及缺少非默认兄弟、路径重复、路径次序错误、共享祖先冲突、单根独立错误等。
3. **HTTP 冒烟**：对真实 API（`http://web:8080`）执行健康、页面、双键通过、
   篡改拒绝、多余节点拒绝、许可见证与各类许可拒绝，并校验失败结论的
   `verification_id` 与此前通过不同。

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
python3 -m unittest discover -s tests # 40 个代码测试
python3 tests/http_smoke.py --spawn   # 自起服务做 HTTP 冒烟
bash tests/run_verify.sh              # 等价于容器内 verify 的全流程
```

## 仓库结构

```
app/smt.py             稀疏树、双树重建、所有拒绝规则、前缀许可分配、参考建树/造证明
app/server.py          标准库 HTTP 服务（/、/healthz、/api/verify、/api/demo）
app/static/            审查页面（HTML/CSS/JS）
tests/test_smt.py      40 个代码测试
tests/http_smoke.py    真实 API 冒烟
tests/run_verify.sh    verify 单次服务的三阶段验收脚本
Dockerfile             python:3.11-slim，内置 HEALTHCHECK
docker-compose.yml     web（可配置宿主端口）+ verify（一次性，退出码验收）
```
