import json
import urllib.request
import urllib.error
from pathlib import Path


def load_key() -> str:
    env_path = Path('.env')
    if not env_path.exists():
        return ''
    for line in env_path.read_text(encoding='utf-8', errors='ignore').splitlines():
        s = line.strip()
        if not s or s.startswith('#') or '=' not in s:
            continue
        key, value = s.split('=', 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key in ('GEMINI_API_KEY', 'GOOGLE_API_KEY', 'GOOGLE_GENAI_API_KEY') and value:
            return value
    return ''


def main() -> int:
    api_key = load_key()
    if not api_key:
        print('RESULT: NO_API_KEY_FOUND')
        return 2

    url = (
        'https://generativelanguage.googleapis.com/v1beta/'
        f'models/gemini-2.5-pro:generateContent?key={api_key}'
    )
    payload = json.dumps(
        {'contents': [{'parts': [{'text': 'Reply with exactly PRO_OK'}]}]}
    ).encode('utf-8')
    req = urllib.request.Request(
        url,
        data=payload,
        headers={'Content-Type': 'application/json'},
        method='POST',
    )

    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            body = resp.read().decode('utf-8', errors='ignore')
            data = json.loads(body)
            text = data.get('candidates', [{}])[0].get('content', {}).get('parts', [{}])[0].get('text', '')
            print('RESULT: SUCCESS')
            print('MODEL_RESPONSE: ' + text)
            return 0
    except urllib.error.HTTPError as exc:
        print('RESULT: ERROR')
        print(f'HTTP_STATUS: {exc.code}')
        print('ERROR_BODY: ' + exc.read().decode('utf-8', errors='ignore'))
        return 1
    except Exception as exc:
        print('RESULT: ERROR')
        print('ERROR_MSG: ' + str(exc))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
