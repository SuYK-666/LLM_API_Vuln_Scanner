# LLM-Driven Web API 越权漏洞智能探测与风险可视化评估系统

[English Version](README_EN.md)

本项目是一个面向 Web API 越权（IDOR/垂直越权）场景的智能化检测系统。
它结合了请求流量重放、DeepSeek 大模型推理、差异分析与可视化报告，支持从“抓包输入”到“风险证据输出”的完整闭环。

![figure](figure.jpg)

## 1. 项目目标

传统规则扫描器对 SQL 注入、XSS 等语法型漏洞有效，但难以理解业务语义与授权边界。
本项目通过 LLM 理解 API 请求语义，自动构造越权变异请求，并基于状态码、内容结构、敏感信息等信号进行风险判定。

## 2. 核心能力

1. 流量解析：解析 HAR，提取 API 请求并过滤静态资源。
2. 智能变异：调用 DeepSeek 生成 IDOR/越权测试载荷。
3. 自动重放：保留原始认证头，注入变异参数进行攻击重放。
4. 风险分析：综合状态码、文本相似度、JSON 结构重合度、敏感信息命中进行评分。
5. 防护建议：自动生成修复建议（即时修复、工程加固、监控检测）。
6. 可视化输出：生成 Markdown/HTML 报告，展示证据链与结论。
7. 可追溯日志：每次运行生成独立日志文件，记录完整执行细节。

## 3. 目录结构

```text
LLM_API_Vuln_Scanner/
├── main.py
├── requirements.txt
├── README.md
├── README_EN.md
├── config/
│   ├── config.yaml
│   └── settings.py
├── core/
│   ├── parser.py
│   ├── llm_agent.py
│   ├── scanner.py
│   └── analyzer.py
├── prompts/
│   ├── idor_prompt.txt
│   └── mitigation_prompt.txt
├── data/
│   ├── input/
│   └── output/
├── report/
│   ├── report_generator.py
│   ├── output_report.md
│   ├── output_report.html
│   └── templates/
├── local_lab/
│   ├── vuln_api.py
│   ├── generate_har.py
│   └── README.md
└── logs/
```

## 4. 执行流程（主程序）

`main.py` 运行时的阶段如下：

1. Phase 1：解析 HAR 并重放基线请求。
2. Phase 2：调用 DeepSeek 生成越权 Payload。
3. Phase 3：重放攻击请求并进行风险分析。
4. 附加：对中高风险结果调用 LLM 生成修复建议。
5. 输出：写入 JSON 结果、Markdown 报告、HTML 报告与运行日志。

## 5. 环境准备

### 5.1 安装依赖

```powershell
pip install -r requirements.txt
```

### 5.2 配置 DeepSeek Key

```powershell
$env:DEEPSEEK_API_KEY="your_deepseek_key"
```

也可在 `config/config.yaml` 中填写 `api_key`，但不推荐明文存储。

## 6. 快速启动（扫描已有 HAR）

1. 准备 HAR 文件放入 `data/input/`。
2. 在 `config/config.yaml` 中设置 `input_har`。
3. 执行：

```powershell
python main.py
```

## 7. 使用项目内置本地靶场

项目已内置一个“故意存在越权漏洞”的本地 API 服务，便于答辩演示。

### 7.1 启动本地靶场

```powershell
python local_lab/vuln_api.py
```

默认监听：`http://127.0.0.1:8000`

### 7.2 生成本地 HAR

```powershell
python local_lab/generate_har.py
```

输出文件：`data/input/local_lab.har`

### 7.3 运行扫描

```powershell
python main.py
```

> 默认配置已经指向本地靶场：
>
> - `target_url: http://127.0.0.1:8000`
> - `input_har: data/input/local_lab.har`

## 8. 关键输出说明

运行后会生成以下文件：

1. `data/output/phase1_replay_results.json`：基线请求重放结果。
2. `data/output/phase2_payloads.json`：LLM 生成的攻击载荷。
3. `data/output/phase3_attack_results.json`：攻击重放结果。
4. `data/output/phase3_analysis.json`：风险分析结果（含评分和证据）。
5. `report/output_report.md`：Markdown 报告。
6. `report/output_report.html`：HTML 可视化报告。

## 9. 报告内容

报告会展示以下关键模块：

1. 风险对象：Method + URL。
2. 触发条件：认证保持不变下的参数篡改方式。
3. 风险证据：
   - Baseline/Attack 状态码
   - 相似度
   - JSON 结构重合度（shared/baseline/overlap）
   - Sensitive Hits 命中
   - 响应对比预览
4. 影响分析：结合风险级别自动给出解释。
5. 展示结论：Risk Level + Score。
6. 防护与缓解建议：含即时修复、工程加固、监控建议。

## 10. 日志系统

每次运行会创建一个新的日志文件：

- `logs/run_YYYYMMDD_HHMMSS.log`

日志包含：

1. 阶段开始/结束时间。
2. HAR 解析细节。
3. 每次基线与攻击请求重放记录。
4. LLM 调用与重试信息。
5. 分析器评分信号（相似度、结构重合、敏感命中）。
6. 报告生成与文件写入信息。

## 11. 合规与安全说明

1. 本项目仅用于授权安全测试与教学研究。
2. 请勿对未授权目标执行扫描。
