import json
import logging
from pathlib import Path

from config.settings import load_config
from core.analyzer import analyze_results
from core.llm_agent import attach_mitigation_to_findings, generate_payloads_batch, localize_analysis_language
from core.parser import parse_har_file
from core.scanner import replay_attack_requests, replay_original_requests
from report.report_generator import generate_html_report, generate_markdown_report
from utils.logger import setup_run_logger


def main() -> None:
    log_path = setup_run_logger(log_dir="logs")
    logger = logging.getLogger("main")
    logger.info("==== New Scan Run Started ====")
    logger.info("Log file: %s", log_path)

    config = load_config("config/config.yaml")
    logger.info("Configuration loaded from config/config.yaml")
    har_path = config.get("input_har", "data/input/sample.har")
    timeout = int(config.get("timeout", 15))
    proxy = config.get("proxy", "")
    verify_ssl = bool(config.get("verify_ssl", True))
    max_requests = config.get("max_requests")
    output_path = config.get("phase1_output", "data/output/phase1_replay_results.json")
    prompt_path = config.get("idor_prompt_path", "prompts/idor_prompt.txt")
    phase2_output = config.get("phase2_output", "data/output/phase2_payloads.json")
    phase3_attack_output = config.get("phase3_attack_output", "data/output/phase3_attack_results.json")
    analysis_output = config.get("analysis_output", "data/output/phase3_analysis.json")
    report_markdown_zh = config.get("report_markdown_zh", "report/output_report_zh.md")
    report_html_zh = config.get("report_html_zh", "report/output_report_zh.html")
    report_markdown_en = config.get("report_markdown_en", "report/output_report_en.md")
    report_html_en = config.get("report_html_en", "report/output_report_en.html")
    mitigation_prompt_path = config.get("mitigation_prompt_path", "prompts/mitigation_prompt.txt")
    mitigation_min_score = int(config.get("mitigation_min_risk_score", 45))
    logger.debug("Runtime settings: har_path=%s timeout=%s proxy=%s verify_ssl=%s max_requests=%s", har_path, timeout, bool(proxy), verify_ssl, max_requests)

    print("[Phase 1] Starting HAR parse and raw replay...")
    logger.info("Phase 1 start: HAR parsing and baseline replay")
    requests_data = parse_har_file(har_path=har_path, max_entries=max_requests)
    print(f"Parsed API requests: {len(requests_data)}")
    logger.info("Phase 1 parsed requests: %s", len(requests_data))

    if not requests_data:
        print("No API requests found. Check your HAR file or filter rules.")
        logger.warning("No API requests found after parsing. Exiting run.")
        return

    replay_results = replay_original_requests(
        requests_data=requests_data,
        timeout=timeout,
        proxy=proxy,
        verify_ssl=verify_ssl,
    )

    success_count = sum(1 for item in replay_results if item.get("error") is None)
    fail_count = len(replay_results) - success_count
    print(f"Replay done. success={success_count}, failed={fail_count}")
    logger.info("Baseline replay completed: success=%s failed=%s", success_count, fail_count)

    for item in replay_results:
        req = item.get("request", {})
        if item.get("error"):
            error = item["error"]
            print(
                f"[{item['index']}] {req.get('method')} {req.get('url')} -> "
                f"ERROR {error.get('type')}: {error.get('message')}"
            )
            continue

        rsp = item.get("response", {})
        print(
            f"[{item['index']}] {req.get('method')} {req.get('url')} -> "
            f"{rsp.get('status_code')} len={rsp.get('length')} time={rsp.get('elapsed_ms')}ms"
        )

    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(
        json.dumps(replay_results, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"Saved phase-1 replay results to: {output_file}")
    logger.info("Saved phase-1 output: %s", output_file)

    print("\n[Phase 2] Generating IDOR payloads with LLM...")
    logger.info("Phase 2 start: LLM payload generation")
    llm_config = {
        "api_key": config.get("api_key", ""),
        "base_url": config.get("llm_base_url", "https://api.deepseek.com"),
        "model": config.get("llm_model", "deepseek-chat"),
        "llm_timeout": config.get("llm_timeout", 30),
        "max_payloads_per_api": config.get("max_payloads_per_api", 5),
        "llm_retry_times": config.get("llm_retry_times", 3),
        "temperature": config.get("llm_temperature", 0.2),
    }

    payload_results = generate_payloads_batch(
        requests_data=requests_data,
        config=llm_config,
        prompt_path=prompt_path,
    )

    ok_count = sum(1 for item in payload_results if item.get("error") is None)
    total_payloads = sum(item.get("payload_count", 0) for item in payload_results)
    print(
        f"LLM generation done. api_success={ok_count}/{len(payload_results)}, "
        f"payloads={total_payloads}"
    )
    logger.info("Phase 2 completed: api_success=%s total_apis=%s payloads=%s", ok_count, len(payload_results), total_payloads)

    for item in payload_results:
        req = item.get("request", {})
        if item.get("error"):
            err = item["error"]
            print(
                f"[{item['index']}] {req.get('method')} {req.get('url')} -> "
                f"LLM ERROR {err.get('type')}: {err.get('message')}"
            )
            continue
        print(
            f"[{item['index']}] {req.get('method')} {req.get('url')} -> "
            f"payload_count={item.get('payload_count')}"
        )

    phase2_file = Path(phase2_output)
    phase2_file.parent.mkdir(parents=True, exist_ok=True)
    phase2_file.write_text(
        json.dumps(payload_results, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"Saved phase-2 payload results to: {phase2_file}")
    logger.info("Saved phase-2 output: %s", phase2_file)

    print("\n[Phase 3] Replaying attack payloads and evaluating risk...")
    logger.info("Phase 3 start: attack replay and risk evaluation")
    attack_results = replay_attack_requests(
        requests_data=requests_data,
        payload_results=payload_results,
        timeout=timeout,
        proxy=proxy,
        verify_ssl=verify_ssl,
        capture_body_max_chars=int(config.get("capture_body_max_chars", 20000)),
    )

    attack_success = sum(1 for item in attack_results if item.get("error") is None)
    attack_fail = len(attack_results) - attack_success
    print(f"Attack replay done. success={attack_success}, failed={attack_fail}")
    logger.info("Attack replay completed: success=%s failed=%s", attack_success, attack_fail)

    for item in attack_results[:15]:
        req = item.get("request", {})
        payload_name = item.get("payload_name")
        if item.get("error"):
            err = item["error"]
            print(
                f"[REQ#{item.get('request_index')}] {req.get('method')} {req.get('url')} "
                f"payload={payload_name} -> ERROR {err.get('type')}: {err.get('message')}"
            )
        else:
            rsp = item.get("response", {})
            print(
                f"[REQ#{item.get('request_index')}] {req.get('method')} {req.get('url')} "
                f"payload={payload_name} -> {rsp.get('status_code')} len={rsp.get('length')}"
            )

    phase3_attack_file = Path(phase3_attack_output)
    phase3_attack_file.parent.mkdir(parents=True, exist_ok=True)
    phase3_attack_file.write_text(
        json.dumps(attack_results, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"Saved phase-3 attack results to: {phase3_attack_file}")
    logger.info("Saved phase-3 attack output: %s", phase3_attack_file)

    analysis = analyze_results(
        baseline_results=replay_results,
        attack_results=attack_results,
    )

    analysis = attach_mitigation_to_findings(
        analysis=analysis,
        config=llm_config,
        prompt_path=mitigation_prompt_path,
        min_risk_score=mitigation_min_score,
    )

    analysis_file = Path(analysis_output)
    analysis_file.parent.mkdir(parents=True, exist_ok=True)
    analysis_file.write_text(
        json.dumps(analysis, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(
        "Analysis done. "
        f"findings={analysis.get('total_findings', 0)}, overall_risk={analysis.get('overall_risk', 'Unknown')}"
    )
    print(f"Saved analysis to: {analysis_file}")
    logger.info(
        "Analysis summary: findings=%s overall_risk=%s",
        analysis.get("total_findings", 0),
        analysis.get("overall_risk", "Unknown"),
    )
    logger.info("Saved analysis output: %s", analysis_file)

    logger.info("Generating bilingual reports (zh/en)")
    analysis_zh = localize_analysis_language(analysis=analysis, config=llm_config, target_lang="zh")
    analysis_en = localize_analysis_language(analysis=analysis, config=llm_config, target_lang="en")

    report_md_zh_file = Path(report_markdown_zh)
    report_md_zh_file.parent.mkdir(parents=True, exist_ok=True)
    generate_markdown_report(analysis=analysis_zh, output_path=str(report_md_zh_file), language="zh")
    print(f"Generated markdown report (zh): {report_md_zh_file}")
    logger.info("Generated markdown report (zh): %s", report_md_zh_file)

    report_html_zh_file = Path(report_html_zh)
    report_html_zh_file.parent.mkdir(parents=True, exist_ok=True)
    generate_html_report(analysis=analysis_zh, output_path=str(report_html_zh_file), language="zh")
    print(f"Generated HTML report (zh): {report_html_zh_file}")
    logger.info("Generated HTML report (zh): %s", report_html_zh_file)

    report_md_en_file = Path(report_markdown_en)
    report_md_en_file.parent.mkdir(parents=True, exist_ok=True)
    generate_markdown_report(analysis=analysis_en, output_path=str(report_md_en_file), language="en")
    print(f"Generated markdown report (en): {report_md_en_file}")
    logger.info("Generated markdown report (en): %s", report_md_en_file)

    report_html_en_file = Path(report_html_en)
    report_html_en_file.parent.mkdir(parents=True, exist_ok=True)
    generate_html_report(analysis=analysis_en, output_path=str(report_html_en_file), language="en")
    print(f"Generated HTML report (en): {report_html_en_file}")
    logger.info("Generated HTML report (en): %s", report_html_en_file)

    # Remove legacy mixed-language report files now that bilingual outputs are standard.
    legacy_reports = [
        Path("report/output_report.md"),
        Path("report/output_report.html"),
    ]
    for legacy_path in legacy_reports:
        if legacy_path.exists():
            legacy_path.unlink()
            logger.info("Deleted legacy report file: %s", legacy_path)
            print(f"Deleted legacy report file: {legacy_path}")
    logger.info("==== Scan Run Finished ====")


if __name__ == "__main__":
    main()
