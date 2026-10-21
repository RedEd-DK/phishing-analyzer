"""Check AI configuration or run one synthetic analysis; never send email."""
import argparse
import json

from .ai_analysis import OpenAIAnalyzer
from .config import Config
from .security_checks import enrich


def main():
    parser = argparse.ArgumentParser(description='Check AI setup without reading a mailbox or sending email')
    parser.add_argument('--test', action='store_true', help='Make one billable API call using synthetic email evidence only')
    args = parser.parse_args()
    try:
        cfg = Config.from_env()
    except (ValueError, TypeError):
        print('Invalid configuration. Check .env.example.')
        return 2
    print(json.dumps({'mode': cfg.ai_analysis_mode, 'model': cfg.openai_model,
                      'key_configured': bool(cfg.openai_api_key), 'daily_attempt_limit': cfg.ai_daily_limit}))
    if not args.test:
        return 0
    if not cfg.openai_api_key:
        print('Set OPENAI_API_KEY in the local .env file before testing.')
        return 2
    original = {'subject':'Training exercise: unusual credential request',
                'headers':[{'name':'From','value':'training@example.com'}],
                'body_text':'Your account will be closed in one hour. Send your password and MFA code by reply to avoid closure.',
                'body_truncated':False, 'urls':[], 'attachments':[]}
    result = OpenAIAnalyzer(cfg).analyze(enrich({'originals':[original]}))
    # Never print request bodies, credentials, remote errors or any actual mail.
    print(json.dumps({'status':result['status'], 'reason':result.get('reason'),
                      'classification':result.get('result',{}).get('verdict'), 'usage':result.get('usage',{})}))
    return 0 if result['status']=='completed' else 1


if __name__=='__main__':
    raise SystemExit(main())
