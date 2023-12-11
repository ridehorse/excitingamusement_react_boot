import React from "react";
import { Col, Container, Row } from "react-bootstrap";
import axios from "axios";
import { useEffect, useRef, useState } from "react";
import { PersonCircle } from "react-bootstrap-icons";
import { call } from "../service/ApiService";

export function EditProfile() {
  const imageRef = useRef();

  const [imgFile, setImgFile] = useState("");
  const [m_name, setM_name] = useState("");
  const [m_email, setM_email] = useState("");
  // 카카오로그인 확인
  const [kakao, setKakao] = useState("");
  // 네이버로그인 확인
  const [naver, setNaver] = useState("");

  const kakao_name = sessionStorage.getItem("KAKAO_NAME");

  // member정보 받아옴
  useEffect(() => {
    const request = {
      member_id: sessionStorage.getItem("MEMBER_ID"),
    };
    call("/mypage/getMember", "post", request).then((data) => {
      const m_email = data.m_email;
      const m_name = data.m_name;
      const m_image = data.m_image;

      console.log("EditProfile // m_email : " + data.m_email);
      console.log("EditProfile // m_name : " + data.m_name);
      console.log("EditProfile // m_image : " + data.m_image);

      if (sessionStorage.getItem("KAKAO_ID")) {
        setKakao(sessionStorage.getItem("KAKAO_IMAGE"));
      } else if(sessionStorage.getItem("NAVER_ID")) {
        setNaver(sessionStorage.getItem("NAVER_IMAGE"));
      } else{
        setImgFile(m_image);
      }
      setM_name(m_name);
      setM_email(m_email);
    });
  }, []);

  console.log("imgFile : " + imgFile);

  // 적용버튼 활성화 비활성화(사진변경에 따라서)
  const [apply, setApply] = useState(true);

  // 이미지 표현방식 구분(true:경로방식,false:FileReader)
  const [path, setPath] = useState(true);

  // 사진변경 버튼 클릭 -> 파일업로드 버튼 클릭
  function handleClickUpload() {
    imageRef.current.querySelector("#file").click();
  }

  const formData = new FormData();
  // 파일업로드 되어서 변경이 일어나면
  function handleChangeUpload(e) {
    //파일 객체
    console.log(e.target.files[0]);
    const file = e.target.files[0];
    // 이미지를 등록하지 않고 취소를 하면 file이 undefined가 된다.
    if (file === undefined) {
      return;
    } else {
      setApply(false);
    }

    const reader = new FileReader();

    // file(이미지객체)을 Base64 인코딩해 문자열로 표현한다. 이를 이용해 이미지를 직접 표시할 수 있다.(변환값은 readder에 저장)
    reader.readAsDataURL(file);

    reader.onloadend = () => {
      // 인코딩된 값을 result로 표출
      setImgFile(reader.result);
      console.log(reader.result);
      setPath(false);
    };
  }

  //   적용하기 버튼 클릭
  function handleClickApply() {
    const confirm = window.confirm(
      "이미지를 적용하면 작성한 내용들이 초기화 됩니다. 적용 하시겠습니까?"
    );

    if (confirm) {
      console.log(imageRef.current.querySelector("#file").files[0]);
      const file = imageRef.current.querySelector("#file").files[0];
      console.log("file : " + file);
      formData.append("file", file);
      formData.append("member_id", sessionStorage.getItem("MEMBER_ID"));

      const access_token = localStorage.getItem("ACCESS_TOKEN");
      console.log(access_token);

      axios({
        method: "POST",
        url: "http://localhost:8080/mypage/upload",
        headers: {
          "content-Type": "multipart/form-data",
          Authorization: "Bearer " + access_token,
        },
        data: formData,
      })
        .then((res) => {
          console.log(res.data);
          window.location.href = "/editMember";
        })
        .catch((err) => {
          console.log(err);
        });
    } else {
      return;
    }
  }

  //   삭제 버튼 클릭
  function handleClickDelete() {
    const request = {
      member_id: sessionStorage.getItem("MEMBER_ID"),
    };
    call("/mypage/getMember", "post", request).then((data) => {
      const m_image = data.m_image;

      setImgFile(m_image);
      setPath(true);
    });
  }

  return (
    <div ref={imageRef} style={{ marginTop: "50px" }} className="px-0">
      <Container>
        <Row
          style={{
            borderTop: "1px solid",
            borderBottom: "1px solid",
            borderColor: "lightgray",
          }}
        >
          <Col
            sm={3}
            className="pt-5"
            style={{ background: "rgba(128, 128, 128, 0.1)" }}
          >
            <div
              className="ps-3"
              style={{ fontSize: "14px", fontWeight: "bold" }}
            >
              프로필 사진
            </div>
          </Col>
          <Col
            sm={9}
            className="ps-5 pt-4 pb-4"
            style={{ borderLeft: "1px solid", borderColor: "lightgray" }}
          >
            <div
              style={{ width: "120px", height: "110px" }}
              className="d-flex justify-content-center"
            >
              {imgFile ? (
                path ? (
                  <img
                    src={require("../img/profileImg/" + imgFile)}
                    style={{ width: "120px", heigh: "90px" }}
                    className="border rounded-circle"
                    alt="일반로그인(사진등록되어있음)"
                  />
                ) : (
                  <img
                    src={imgFile}
                    style={{ width: "120px", heigh: "90px" }}
                    className="border rounded-circle"
                    alt="일반로그인(사진변경 직후)"
                  />
                )
              ) : kakao ? (
                <img
                  src={kakao}
                  style={{ width: "120px", heigh: "90px" }}
                  className="border rounded-circle"
                  alt="카카오 로그인"
                />
              ) : naver ? (
                <img
                  src={naver}
                  style={{ width: "120px", heigh: "90px" }}
                  className="border rounded-circle"
                  alt="네이버 로그인"
                />
              ):(
                <PersonCircle style={{ width: "120px", height: "90px" }} />
              )}
            </div>
            <div className="mt-4">
              {kakao ? (
                <span
                  style={{
                    fontWeight: "bold",
                    color: "rgba(100, 80, 180, 0.9)",
                  }}
                >
                  카카오아이디로 접속중입니다
                </span>
              ) : naver ? (
                <span
                style={{
                  fontWeight: "bold",
                  color: "rgba(100, 80, 180, 0.9)",
                }}
              >
                네이버아이디로 접속중입니다
              </span>
              ) : (
                <div>
                  <input
                    accept="image/*"
                    type="file"
                    name="file"
                    id="file"
                    onChange={handleChangeUpload}
                    style={{ display: "None" }}
                  />
                  <input
                    onClick={handleClickUpload}
                    style={{
                      marginRight: "10px",
                      width: "100px",
                      height: "35px",
                      fontSize: "13px",
                      fontWeight: "bold",
                      background: "white",
                      borderRadius: "1px",
                      border: "1px solid",
                      borderColor: "rgba(0, 0, 0, 0.3)",
                    }}
                    type="button"
                    value="사진변경"
                  ></input>
                  <input
                    style={{
                      marginRight: "10px",
                      width: "100px",
                      height: "35px",
                      fontSize: "13px",
                      fontWeight: "bold",
                      background: "rgba(110, 72, 300, 0.7)",
                      borderRadius: "1px",
                      border: "0px solid",
                    }}
                    onClick={handleClickApply}
                    type="button"
                    value="적용하기"
                    disabled={apply}
                  ></input>
                  <input
                    style={{
                      color: "rgba(128, 128, 128, 0.9)",
                      width: "80px",
                      height: "35px",
                      fontSize: "13px",
                      fontWeight: "bold",
                      background: "white",
                      borderRadius: "1px",
                      border: "1px solid",
                      borderColor: "rgba(0, 0, 0, 0.3)",
                    }}
                    onClick={handleClickDelete}
                    type="button"
                    value="삭제"
                    disabled={apply}
                  ></input>
                </div>
              )}
            </div>
          </Col>
        </Row>
        <Row style={{ borderBottom: "1px solid", borderColor: "lightgray" }}>
          <Col
            sm={3}
            style={{
              paddingTop: "23px",
              background: "rgba(128, 128, 128, 0.1)",
            }}
          >
            <div
              className="ps-3"
              style={{ fontSize: "14px", fontWeight: "bold" }}
            >
              이름
            </div>
          </Col>
          <Col
            sm={9}
            className="ps-5"
            style={{
              paddingTop: "22px",
              paddingBottom: "22px",
              borderLeft: "1px solid",
              borderColor: "lightgray",
            }}
          >
            <div>{kakao_name ? kakao_name : m_name}</div>
          </Col>
        </Row>
        <Row style={{ borderBottom: "1px solid", borderColor: "lightgray" }}>
          <Col
            sm={3}
            style={{
              paddingTop: "23px",
              background: "rgba(128, 128, 128, 0.1)",
            }}
          >
            <div
              className="ps-3"
              style={{ fontSize: "14px", fontWeight: "bold" }}
            >
              이메일
            </div>
          </Col>
          <Col
            sm={9}
            className="ps-5"
            style={{
              paddingTop: "22px",
              paddingBottom: "22px",
              borderLeft: "1px solid",
              borderColor: "lightgray",
            }}
          >
            <div>{m_email}</div>
          </Col>
        </Row>
      </Container>
    </div>
  );
}
