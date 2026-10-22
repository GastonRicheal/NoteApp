# Project 1：三分钟展示讲稿

默认提交和展示使用英文，下面附中文讲解。六页总预算为 **180 秒**，英文讲稿约 360 词，按每分钟 125–135 词练习，并留少量换页时间。当前确认作者为 ZHANG FANGYUCHEN，由其完成六页展示；不虚构其他组员或分工。课件要求 3–4 人组队，人数安排需与教师确认。

## Slide 1 — NotesApp threat model（20 秒）

Our model covers the current NotesApp: browsers, Flask, PostgreSQL and its Docker deployment. We protect grades, comments, credentials and administrator authority. We reviewed the source and checked runtime permissions. We did not execute attacks. Our baseline includes the AES-GCM homework, with all sixty comments stored in encrypted form.

中文理解：交代范围、保护什么、怎样获取证据。使用加密后的当前版本做分析，避免把已经完成的评论加密写成“还没做”。

## Slide 2 — Application data flows（25 秒）

Students read their records. Teachers write grades and export comments. Admins manage users and submit a ping host. Every arrow has a flow number. TB1 separates browser requests from Flask. TB2 separates Flask from the database. TB3 is the point where a returned comment becomes browser markup. That last boundary explains why stored XSS still matters after encryption.

中文理解：F 编号对应报告中的数据流清单。信任边界不只是网络，还包括“数据被当成代码解释”的位置。

## Slide 3 — Deployment and privileged flows（25 秒）

The deployment adds key loading, audit writes and the operating-system command runner. The web process runs as root. It also has the Docker socket and a writable host project mount. These cross TB4, TB5 and TB6. On Docker Desktop, the socket controls the Linux Docker engine. We do not claim that this alone proves Windows kernel administrator access.

中文理解：容器内部 root、Linux Docker 引擎控制、Windows 管理员权限是不同范围。我们只声称配置和权限能支持的影响。

## Slide 4 — STRIDE and risk scoring（35 秒）

We identified sixteen concrete threats across all six STRIDE categories. For example, login injection spoofs identity, unchecked teacher writes tamper with grades, weak logs allow repudiation, and note IDs expose another student's data. Unbounded requests threaten availability. Shell execution can elevate privileges. We score likelihood and impact from one to five. These are qualitative judgments. Prerequisites and scoring reasons appear in the report.

中文理解：六类必须覆盖；每一项有可能性、影响及理由。“4×5=20”不是说有 80% 的攻击成功率。

## Slide 5 — Top three remediation priorities（45 秒）

First, fix login SQL injection, rated twenty-five. Bind query parameters, verify password hashes and limit database privileges. Second, fix shell execution with Docker access, rated twenty. Remove the command feature or strictly validate inputs, remove the socket and host mount, and run as non-root. Third, replace the public session signing key, also rated twenty. Invalidate old cookies and verify current roles server-side. These are proposals. The lower residual scores are targets that require acceptance tests.

中文理解：前三项修复要说明具体做什么、为什么优先、怎样验收。不能把建议说成我们已经修复，也不能把预期分数说成测试结果。

## Slide 6 — AES-GCM and the next decision（30 秒）

AES-GCM protects stored comment payloads and detects changes to those payloads and their note IDs. The application still decrypts comments before returning them. Therefore, IDOR can expose plaintext, unescaped HTML can execute, and application compromise can expose the key. After the top three, we recommend fixing student ownership and teacher class scoping, both rated sixteen. Encryption must sit alongside access control.

中文理解：加密能做什么、做不到什么是结尾重点。先修前三项，后续立即处理学生越权读取和教师跨班级操作。

## 常见追问

**为什么不把 IDOR 放进前三项？**

它是高风险，评分为 4×4=16。登录注入是 5×5=25；公开会话密钥和 root 命令执行分别能进入管理员权限与 Docker 控制面，评分为 4×5=20。评分依赖本项目明确写出的前提；若部署关闭管理员功能或撤掉危险挂载，排序需要调整。

**为什么 JWT 的 alg:none 没有直接写成管理员页面提权？**

API 使用 `current_identity()` 接受 Bearer 身份，但教师和管理员页面的 `login_required()` 检查的是 Flask session。JWT 伪造直接影响 API 身份，伪造管理员网页会话的证据是公开的 Flask 签名密钥，两条路径不能混为一谈。

**既然评论有认证标签，数据库修改还有什么风险？**

AAD 只绑定 `note.id`，没有绑定 `grade`、`student_id`、`class_id`，也不提供记录的新旧顺序证明。数据库写入者可以修改这些明文字段，或恢复同一 id 的旧有效密文。标签不是整张数据库的签名。

**为什么 CSRF 的可能性只有 3？**

服务器确实没有 token 校验，但浏览器是否带上会话 cookie 取决于 SameSite、站点关系等条件。报告没有把所有跨站 POST 都说成已经成功的攻击。

**现在所有修复都已完成吗？**

评论加密作业已完成。Project 1 的成果是威胁模型、风险分析和修复方案，前三项修复尚未实施；预期风险下降只是待验证目标。
