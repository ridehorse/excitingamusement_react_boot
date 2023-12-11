export function SessionRemove() {
  sessionStorage.removeItem("MEMBER_ID");
  sessionStorage.removeItem("KAKAO_ID");
  sessionStorage.removeItem("KAKAO_IMAGE");
  sessionStorage.removeItem("KAKAO_NAME");
  sessionStorage.removeItem("ADMIN");
  sessionStorage.removeItem("GIT_ID");
  sessionStorage.removeItem("NAVER_ID");
  localStorage.removeItem("ACCESS_TOKEN");
}
