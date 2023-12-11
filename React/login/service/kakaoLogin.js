import React, { useEffect, useRef, useState } from "react";

import { call } from "./ApiService";
import { useSearchParams } from "react-router-dom";
import { openPopup } from "./popUp";

export function KakaoLogin() {
  let [query, setQuery] = useSearchParams();
  const code = query.get("code");
  console.log("kakaoLogin/code :" + code);
  if (code !== null) {
    console.log("KAKAOTOKENGETDATA 매서드 진입");
    const payload = {
      grant_type: "authorization_code",
      client_id: "3c41834efa9c843d49a5db035d348ae7",
      redirect_uri: "http://localhost:3000/kakaoLogin",
      code: code,
    };

    const requestOptions = {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded;charset=utf-8",
      },
      body: new URLSearchParams(payload),
    };

    fetch("https://kauth.kakao.com/oauth/token", requestOptions)
      .then((response) => response.json())
      .then((tokenData) => {
        console.log("밑에 tokenData");
        console.log(tokenData);

        const url = "https://kapi.kakao.com/v2/user/me";
        const headers = {
          "Content-Type": "application/x-www-form-urlencoded",
          Authorization: `bearer ${tokenData.access_token}`,
        };

        const data = new URLSearchParams();
        data.append(
          "property_keys",
          '["kakao_account.email","kakao_account.profile","kakao_account.name","kakao_account.birthday"]'
        );

        const requestOptions = {
          method: "POST",
          headers: headers,
          body: data,
        };

        fetch(url, requestOptions)
          .then((response) => response.json())
          .then((userData) => {
            console.log("토큰으로 카카오정보 얻기 성공");
            const nickname = userData.kakao_account.profile.nickname;
            const birthday = userData.kakao_account.birthday;
            const profile_image =
              userData.kakao_account.profile.profile_image_url;
            const email = userData.kakao_account.email;
            const id = userData.id;

            console.log("토근으로 카카오정보 얻기 성공 /id : " + nickname);
            console.log("토근으로 카카오정보 얻기 성공 /id : " + birthday);
            console.log("토근으로 카카오정보 얻기 성공 /id : " + profile_image);
            console.log("토근으로 카카오정보 얻기 성공 /id : " + email);
            console.log("토근으로 카카오정보 얻기 성공 /id : " + id);

            const request = {
              m_kakao_id: id,
            };

            call("/login/kakaoLogin", "POST", request)
              .then((data) => {
                console.log(
                  "DB에 카카오아이디 저장되어있는지 확인하는 통신 응답받음" +
                    data
                );
                if (data === true) {
                  console.log("DB에 아이디 존재");
                  // 이전페이지경로(/main 형태)
                  window.close();
                  window.opener.location.href = `/kakaoInter?kakaoId=${id}&kakaoImage=${profile_image}&kakaoName=${nickname}`;
                  console.log(
                    `/main?kakaoId=${id}&kakaoImage=${profile_image}&kakaoName=${nickname}`
                  );
                } else if (data === false) {
                  // 회원가입창으로 이동, session만들면 안됨, 로그인한게 아님
                  // 부모창으로 data 전달(부모창에서 event로 받음)
                  console.log("DB에 아이디 존재안함 / KAKAO_ID : " + id);
                  window.close();
                  window.opener.location.href = `/signup?kakaoId=${id}`;
                } else {
                  console.log("응답 제대로 안옴");
                }
              })
              .catch((err) => {
                console.log(
                  "DB에 카카오아이디 저장되어있는지 확인하는작업 통신 오류"
                );
                console.log(err);
              });
          })
          .catch((error) => {
            console.error("Error:", error);
          });
      })
      .catch((error) => {
        console.error("Error:", error);
      });
  }
}

export function kakaoAuth() {
  const url =
    "https://kauth.kakao.com/oauth/authorize?client_id=3c41834efa9c843d49a5db035d348ae7&redirect_uri=http://localhost:3000/kakaoLogin&response_type=code&scope=profile_image,profile_nickname,birthday,account_email&prompt=login";

  openPopup(url);
}
