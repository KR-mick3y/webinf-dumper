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

Burp Suite 프록시를 거쳐서 실행하려면:

```bash
python3 webinf_dumper.py https://target.com/WEB-INF \
  -o output \
  --proxy http://127.0.0.1:8080
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

## 만든이

mick3y
