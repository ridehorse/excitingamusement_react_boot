import { API_BASE_URL } from "../../api.config";

export function call(api, method, request) {
  let headers = new Headers({
    "Content-Type": "application/json",
  });

  // login했을때 token이 발급된다. 그 이후에 다른 페이지로 이동할때부터는 controller에서 token을 확인하게 되고 이때문에
  // token을 헤더가 추가해서 보낸다.
  // token이 없다면 bearer을 추가하지 않고 token이 있따고 bearer을 추가한다.
  // bearer 존재여부에 따른 작업은 springboot의 security가 할 것이다.
  const accessToken = localStorage.getItem("ACCESS_TOKEN");
  if (accessToken && accessToken !== null) {
    headers.append("Authorization", "Bearer " + accessToken);
  }

  let options = {
    headers: headers,
    url: API_BASE_URL + api,
    method: method,
  };
  if (request) {
    options.body = JSON.stringify(request);
  }
  return fetch(options.url, options)
    .then((response) => {
      console.log(options.url + " : apiService 응답받음");
      if (response.status === 200) {
        return response.json();
      }
    })
    .catch((error) => {
      console.log(options.url + " : http error");
      console.log(error);
    });
}

export function login(memberDTO, longLogin, formData, setErrorMessage) {
  return call("/login/signin", "POST", memberDTO)
    .then((response) => {
      if (response.token) {
        localStorage.setItem("ACCESS_TOKEN", response.token);
        sessionStorage.setItem("MEMBER_ID", formData.member_id);
        if (response.roles === "ROLE_admin") {
          sessionStorage.setItem("ADMIN", "admin");
        }

        // 로그인 버튼 눌렀을 떄 '아이디 자동입력 체크 상태" 확인 후 local 생성
        if (longLogin) {
          localStorage.setItem("LONG_LOGIN", "true");
          localStorage.setItem("MEMBER_ID", formData.member_id);
        } else {
          localStorage.setItem("LONG_LOGIN", "false");
          localStorage.removeItem("MEMBER_ID");
        }

        console.log(response.token);

        //이전 페이지로 돌아가기
        const pathName = new URL(document.referrer).pathname;
        const params = new URL(document.referrer).searchParams;
        if (
          pathName === "/login" ||
          pathName === null ||
          pathName === "/signup" ||
          pathName === "/signUpComplete" ||
          pathName === "/searchPw" ||
          pathName === "/newPw" ||
          pathName === "/pwComplete"
        ) {
          window.location.href = "/";
        } else {
          window.location.href = pathName + `?${params}`;
        }
      }
    })
    .catch((error) => {
      // 로그인 눌렀을 시 사용자 정보가 일치하지 않을경우 이곳으로 옮
      console.error("사용자 정보가 일치하지 않습니다.", error);
      setErrorMessage("정보가 일치하지 않습니다.");
    });
}

export function socialLogin(provider) {
  // http://localhost:8080/auth/authrize/github?redirect_uri="http://localhost:3000" 형태로 전달된다.
  // "/auth/authorize" 는 백엔드서버(springboot)에서 authorizationEndpoint()의 baseUri()의 등록된 주소이다.
  // "/auth/authorize" 주소는 github서버의 주소와는 관련이 없고 내가 임의로 정한 주소이다.
  // redirect_uri 값은 클라이언트가 어떤 ip에서 시작하는지 백엔드서버에서 쿠키로 저장하기 위해 보내는 값이다.
  window.location.href =
    API_BASE_URL +
    "/auth/authorize/" +
    provider +
    "?redirect_uri=" +
    // http://localhost:3000 까지
    window.location.origin;
}

export function EditMemberCom(formData) {
  const request = {
    member_id: formData.member_id,
    m_email: formData.m_email,
    m_birth: formData.m_birth,
    m_phone: formData.m_phone,
    m_address: formData.m_address,
  };

  console.log("밑에 hanldeClickHidden 들어간 후 formData");
  console.log(formData);
  console.log("formData.m_address : " + formData.m_address);
  console.log("formData.m_email : " + formData.m_email);
  console.log("formData.m_birth : " + formData.m_birth);
  console.log("formData.m_phone : " + formData.m_phone);

  call("/mypage/editMember", "POST", request).then((response) => {
    if (response === 1) {
      console.log("editmember 수정 성공");
      alert("정보수정이 성공적으로 완료되었습니다.");
      // window.location.href = "/main";
    } else {
      console.log("editmember 수정 실패");
    }
  });
}
