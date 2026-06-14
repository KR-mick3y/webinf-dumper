# WEB-INF dumper

Java 웹 애플리케이션에서 외부로 노출된 `WEB-INF`, `META-INF`, `BOOT-INF` 리소스를 따라가며 내려받는 도구입니다.

단순히 워드리스트만 때리는 방식이 아니라, 먼저 받은 설정 파일을 분석해서 다음 파일을 찾아갑니다. 예를 들어 `web.xml`에서 Spring 설정 파일을 찾고, Spring 설정에서 iBATIS/MyBatis 설정을 찾고, SQL map이나 class 파일에서 다시 관련 class, JSP, 이미지 등을 이어서 수집합니다.

요청은 기본적으로 `GET`만 사용합니다. 파일 업로드, POST 요청, 데이터 수정/삭제 같은 동작은 하지 않습니다.

## 구성 파일

```text
webinf_dumper.py      실행 파일
web-inf.txt           기본 WEB-INF 전용 워드리스트
cfr-0.152.jar         class 디컴파일용 CFR
```

`cfr-0.152.jar`는 `--cfr-jar` 옵션을 주지 않아도 실행 파일과 같은 디렉터리에 있으면 자동으로 사용합니다.

## 기본 사용법

```bash
cd /tmp/webinf-dumper
python3 webinf_dumper.py https://target.com/WEB-INF -o output
```

Burp Suite 프록시를 거쳐서 실행하려면:

```bash
python3 webinf_dumper.py https://target.com/WEB-INF \
  -o output \
  --proxy http://127.0.0.1:8080
```

대상 URL은 아래처럼 줄 수 있습니다.

```text
https://target.com/
https://target.com/WEB-INF
https://target.com/WEB-INF/web.xml
```

## 자주 쓰는 옵션

```text
--wordlist PATH       기본값은 현재 디렉터리의 web-inf.txt
--proxy URL           프록시 사용. 예: http://127.0.0.1:8080
--headers-file PATH   추가 헤더 파일 사용
--timeout 15          요청 타임아웃
--max-workers 3       동시 요청 수
--max-depth 20        재귀 분석 깊이
--max-requests 0      최대 요청 수. 0은 제한 없음
--no-bruteforce       초기 워드리스트 요청 생략
--no-decompile        CFR 디컴파일 생략
--cfr-jar PATH        CFR jar 직접 지정
--allow-cross-host    다른 호스트 URL도 허용
--keep-error-like     에러 페이지로 보이는 응답도 저장
--debug               디버그 출력
```

버전 확인:

```bash
python3 webinf_dumper.py --version
```

## 결과물 구조

실행이 끝나면 `-o`로 지정한 디렉터리에 아래 구조가 생깁니다.

```text
output/
  raw/             내려받은 원본 파일
  decompiled/      CFR로 디컴파일한 Java 파일
  reports/
    inventory.json
    fetch_log.tsv
    discovered_refs.tsv
    skipped.tsv
    summary.md
```

주로 보면 되는 파일은 `reports/summary.md`와 `reports/fetch_log.tsv`입니다.

- `summary.md`: 전체 수집 요약
- `fetch_log.tsv`: 요청별 상태, 저장 경로, 에러 여부
- `discovered_refs.tsv`: 어떤 파일에서 어떤 참조를 발견했는지
- `skipped.tsv`: 외부 URL, 실행형 endpoint 등 일부러 요청하지 않은 항목
- `inventory.json`: 전체 상세 결과

## 동작 방식

대략 이런 순서로 움직입니다.

1. 대상의 `WEB-INF/web.xml`, `WEB-INF/`, `META-INF/MANIFEST.MF`를 먼저 확인합니다.
2. `web-inf.txt`에 있는 Java 웹앱 주요 경로를 요청합니다.
3. 실제 파일로 보이는 응답만 저장합니다.
4. 커스텀 404처럼 보이는 `200 OK` 에러 페이지는 저장하지 않습니다.
5. 받은 XML, properties, YAML, class, JSP, CSS, Java 파일을 분석합니다.
6. 새로 찾은 설정 파일, SQL map, class, JSP, 이미지 등을 다시 큐에 넣습니다.
7. class 파일은 constant pool을 먼저 분석하고, CFR이 있으면 Java로 디컴파일합니다.

진행률은 한 줄 게이지로 표시됩니다. 중간에 `Ctrl+C`를 누르면 `Bye bye`를 출력하고 종료합니다.

## 주의사항

이 도구는 노출된 정적 리소스를 수집하는 용도입니다.

기본적으로 다음 동작은 하지 않습니다.

```text
POST / PUT / PATCH / DELETE 요청
파일 업로드
로그인 시도
ID 순차 대입
업무 기능 endpoint 실행
대량 디렉터리 브루트포스
```

`.do`, `.mc`, `.action`, `/api/...` 같은 업무 endpoint는 기본적으로 요청하지 않고 보고서에만 기록합니다.

진단 대상과 범위가 명확히 승인된 상태에서만 사용하세요.

## 예시

```bash
cd /tmp/webinf-dumper

python3 webinf_dumper.py https://mobile2.skbroadband.com/WEB-INF \
  -o /tmp/skbroadband \
  --proxy http://127.0.0.1:8080
```

수집 결과 확인:

```bash
less /tmp/skbroadband/reports/summary.md
less /tmp/skbroadband/reports/fetch_log.tsv
find /tmp/skbroadband/raw/WEB-INF -type f
find /tmp/skbroadband/decompiled -type f
```

## 만든이

mick3y
