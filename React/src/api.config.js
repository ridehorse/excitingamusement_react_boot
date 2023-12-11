let backendHost;

// window가 존재하고, window.location이 존재하면 window.location.hostname의 값을 전달한다.
const hostname = window && window.location && window.location.hostname;

if (hostname === "localhost") {
  backendHost = "http://localhost:8080";
}

// `을 사용하는 이유 : API_BASE_URL이 받는 값은 문자열이다. 그런데
// "" 을 사용하면 ${} 같은 변수명을 담을수가 없다. 그러므로 문자열에서 변수명을 받아올수 있도록 `으로 감싼다.
export const API_BASE_URL = `${backendHost}`;
