import React from "react";
import { call } from "../service/ApiService";
import { searchQuery } from "../service/searchQuery";

export function GithubLogin() {
  const access_token = searchQuery("token");
  const member_id = searchQuery("member_id");
  const git_id = searchQuery("git_id");
  // 회원가입 x : false , 회원가입 o : true
  const result = searchQuery("result");
  localStorage.setItem("ACCESS_TOKEN", access_token);
  sessionStorage.setItem("MEMBER_ID", member_id);
  sessionStorage.setItem("GIT_ID", git_id);

  if (result === "1") {
    window.location.href = "/";
  } else {
    window.location.href = "/signup?git_id=" + git_id;
  }
}

export function KakaoLogin() {
  const access_token = searchQuery("token");
  const member_id = searchQuery("member_id");
  const kakao_id = searchQuery("kakao_id");
  const kakao_image = searchQuery("kakao_image");
  // 회원가입 x : false , 회원가입 o : true
  const result = searchQuery("result");
  localStorage.setItem("ACCESS_TOKEN", access_token);
  sessionStorage.setItem("MEMBER_ID", member_id);
  sessionStorage.setItem("KAKAO_ID", kakao_id);
  sessionStorage.setItem("KAKAO_IMAGE", kakao_image);
  
  if (result === "1") {
    window.location.href = "/";
  } else {
    window.location.href = "/signup?kakao_id=" + kakao_id;
  }
}

export function NaverLogin() {
  const access_token = searchQuery("token");
  const member_id = searchQuery("member_id");
  const naver_id = searchQuery("naver_id");
  const naver_image = searchQuery("naver_image");
  // 회원가입 x : false , 회원가입 o : true
  const result = searchQuery("result");
  localStorage.setItem("ACCESS_TOKEN", access_token);
  sessionStorage.setItem("MEMBER_ID", member_id);
  sessionStorage.setItem("NAVER_ID", naver_id);
  sessionStorage.setItem("NAVER_IMAGE", naver_image);
  
  if (result === "1") {
    window.location.href = "/";
  } else {
    window.location.href = "/signup?naver_id=" + naver_id;
  }
}