# 本地越权靶场

本目录提供一个故意含有授权缺陷的本地 API 靶场，用于在授权范围内验证扫描器对 High / Medium / Low / Info 的分级能力。

## 一、启动方式

在项目根目录执行：

```powershell
python local_lab/vuln_api.py
```

服务地址：`http://127.0.0.1:8000`

健康检查：

```powershell
curl http://127.0.0.1:8000/health
```

## 二、生成 HAR（包含 8 个接口，顺序随机）

```powershell
python local_lab/generate_har.py
```

输出路径：`data/input/local_lab.har`

说明：脚本会将 8 个基线请求随机打乱后再发起，验证扫描流程可处理无序流量。

## 三、8 接口设计矩阵

### A. 高危组（High，预期 80-100）

1. `GET /api/v1/user/profile?uid=1001`

- 类型：水平越权（IDOR）
- 核心问题：仅校验登录，不校验 `uid` 归属。
- 结果：可读他人手机号、身份证、邮箱等高敏信息。

2. `GET /api/v1/order/detail?order_id=50001`

- 类型：水平越权（对象所有权缺失）
- 核心问题：未校验 `order.uid == actor.uid`。
- 结果：可访问他人订单。

3. `GET /api/v1/admin/audit`

- 类型：垂直越权
- 核心问题：缺失角色校验。
- 结果：普通用户可读管理审计信息。

### B. 中危组（Medium，预期 40-75）

4. `GET /api/v1/user/avatar?uid=1001`

- 类型：低敏信息水平越权
- 核心问题：允许跨用户读取头像卡片信息。
- 结果：可读昵称、头像、签名等低敏字段。
- 评分原因：常见为 200 且结构部分一致，但无核心敏感模式命中。

5. `GET /api/v1/user/settings?uid=1001`

- 类型：防御型接口（误报研究样本）
- 核心逻辑：后端忽略传入 `uid`，强制使用 token 中真实 uid。
- 结果：攻击者只拿到自己的配置，不是真正越权。
- 研究价值：可用于观察“高相似度判定”的误报边界。

### C. 低危组（Low，预期 10-30）

6. `GET /api/v1/file/download?file_id=f-1001`

- 类型：异常处理不当
- 核心问题：当 `file_id` 非预期格式时，内部会抛错并返回 500，且带少量内部实现信息。
- 结果：主要反映接口健壮性不足，而非典型越权成功。

### D. 安全组（Secure / Info，预期 0）

7. `GET /api/v1/payment/cards?uid=1001`

- 类型：严格鉴权
- 核心逻辑：显式校验 `uid == actor["uid"]`，不通过直接 403。
- 结果：越权尝试被拦截。

8. `GET /api/v1/system/announcements?id=1`

- 类型：公开数据接口
- 核心逻辑：无需鉴权，返回公开公告数据。
- 结果：参数变异仅影响公开内容，不构成越权。

## 四、运行原理

扫描链路保持一致：

1. 基线重放：先用 HAR 中正常请求采样基线响应。
2. 攻击重放：LLM 生成参数变异（如 `uid`、`order_id`、`file_id`）并重放。
3. 证据评分：结合状态码、响应相似度、JSON 结构重叠、敏感信息命中计算风险。

这 8 个接口通过“敏感程度 + 鉴权强度 + 响应稳定性”组合，天然形成分级阶梯，不再全部堆到满分。

## 五、内置身份

- 普通用户：`user_A_token`、`user_B_token`
- 管理员：`admin_token`

## 六、完整验证步骤

```powershell
python local_lab/vuln_api.py
python local_lab/generate_har.py
python main.py
```

执行后重点查看：

- `data/output/phase3_analysis.json`
- `report/output_report_zh.md`
- `report/output_report_zh.html`

## 七、使用边界

仅用于本地安全研究、教学演示和授权测试，不得用于未授权目标。
