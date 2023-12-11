import React from "react";
import { call } from "../service/ApiService";

export function KakaoInter() {
  const currentParams = new URLSearchParams(window.location.search);
  const kakao_id = currentParams.get("kakaoId");
  const kakao_image = currentParams.get("kakaoImage");
  const nickName = currentParams.get("kakaoName");
  console.log(kakao_id, kakao_image);
  console.log("nickName: " + nickName);

  sessionStorage.setItem("KAKAO_ID", kakao_id);
  console.log("KakaoInter 진입 / kakao_id : " + kakao_id);
  const request = {
    m_kakao_id: kakao_id,
  };
  call("/mypage/getMemberByKakaoId", "POST", request)
    .then((data) => {
      console.log("member_id: " + data.member_id);
      console.log("m_pass: " + data.m_pass);
      sessionStorage.setItem("MEMBER_ID", data.member_id);
      sessionStorage.setItem("KAKAO_IMAGE", kakao_image);
      sessionStorage.setItem("KAKAO_NAME", nickName);

      const request = {
        member_id: data.member_id,
        m_pass: data.m_pass,
      };
      call("/login/kakaoSignin", "POST", request)
        .then((data) => {
          console.log("/login/kakaoSignin : data.token");
          console.log(data.token);
          localStorage.setItem("ACCESS_TOKEN", data.token);
        })
        .catch((err) => {
          console.log("kakaoSignin error" + err);
          alert("로그인에 실패했습니다. 다시 시도해주세요.");
          window.location.href = "/login";
        });
      window.location.href = "/";
    })
    .catch((err) => {
      console.log("getMemberBykakaoId error : " + err);
    });

  return;
}
