import React, { useState } from "react";
import { login, socialLogin } from "../service/ApiService";

import Container from "react-bootstrap/Container";
import Row from "react-bootstrap/Row";
import Col from "react-bootstrap/Col";
import { Link } from "react-router-dom";
import { ErrorMessage } from "../service/Messaging";
import { kakaoAuth } from "../service/kakaoLogin";

const Login = () => {
  // 카카오 로그인시 받아오는 정보저장
  const [userData, setUserData] = useState({});
  console.log("로그인 페이지 들어옴");

  // 로그인페이지 들어왔을 때 아이디 자동입력 체크 여부 확인(체크o : true / 체크x : false)(초기값 설정)
  // true 이면 checkbox에 체크된다.
  const local = localStorage.getItem("LONG_LOGIN");
  let long_login = false;
  let member_id = "";
  if (local === "" || local === null) {
    localStorage.setItem("LONG_LOGIN", "false");
  }
  // local 에 담긴값은 STRING 이여서 boolean으로 변경해 줘야 checked가 인식됨
  if (local === "false") {
    long_login = false;
  } else if (local === "true") {
    long_login = true;
    member_id = localStorage.getItem("MEMBER_ID");
  }

  const [longLogin, setLongLogin] = useState(long_login);
  const [formData, setFormData] = useState({
    member_id: member_id,
    m_pass: "",
  });

  const [errorMessage, setErrorMessage] = useState();

  // LOGIN button css 스타일
  const buttonStyle = {
    width: "100%",
    height: "50px",
    background: "#5a83c5",
    color: "#fff",
    fontSize: "20px",
    border: "none",
    borderRadius: "1px",
    cursor: "pointer",
  };

  // LOGIN 버튼 클릭하면 일반로그인
  function handleSubmit(e) {
    e.preventDefault();
    setErrorMessage("");
    // login/signin과 통신하는 컴포넌트(+아이디자동입력 용 session 생성)
    login(formData, longLogin, formData, setErrorMessage);
  }

  // 카카오버튼 클릭
  const handleClickKakao = (provider) => {
    // 인가키 받아오기
    //kakaoAuth();
    socialLogin(provider);
  };

  // 깃허브버튼 클릭
  const handleClickGithub = (provider) => {
    socialLogin(provider);
  };

  // 네이버 클릭
  const handleClickNaver = (provider) => {
    socialLogin(provider);
  };

  function handleInputChange(e) {
    const { name, value } = e.target;

    console.log("name : " + name + " , value : " + value);
    setFormData((prevData) => ({
      ...prevData,
      [name]: value,
    }));
  }

  // 아이디 자동입력 체크 이벤트
  function handleLongLogin(e) {
    setLongLogin(longLogin ? false : true);
  }

  return (
    <div className="d-flex justify-content-center">
      <div style={{ width: "540px" }}>
        <Container>
          <Row className="mt-5 mb-5 d-flex justify-content-center">
            <img
              src={require("../img/excitingamusement.png")}
              alt="logo"
              style={{ width: "350px" }}
            />
          </Row>
        </Container>

        <Container style={{ width: "400px" }}>
          <Row className="mb-5">
            <label className="form-check-label" htmlFor="long_login">
              <input
                onChange={handleLongLogin}
                className="form-check-input"
                type="checkbox"
                id="long_login"
                name="long_login"
                checked={longLogin}
              />
              <span className="ms-2" style={{ fontSize: "15px" }}>
                아이디 자동입력
              </span>
            </label>
          </Row>

          <form onSubmit={handleSubmit}>
            <Row className="mb-4">
              <input
                className="border-0 border-bottom"
                type="text"
                name="member_id"
                id="member_id"
                style={{ outline: "none" }}
                placeholder="아이디"
                onChange={handleInputChange}
                value={formData.member_id}
                required
              />
            </Row>
            <Row>
              <input
                className="border-0 border-bottom"
                type="password"
                name="m_pass"
                id="m_pass"
                style={{ outline: "none" }}
                placeholder="비밀번호"
                onChange={handleInputChange}
                required
              />
            </Row>
            <ErrorMessage errorMessage={errorMessage} />

            <Row className="mb-3 mt-5">
              <Col className="d-flex justify-content-center">
                <button id="btn" type="submit" style={buttonStyle}>
                  LOGIN
                </button>
              </Col>
            </Row>
          </form>

          <Row style={{ marginBottom: "90px" }}>
            <Col sm={6}></Col>
            <Col
              className="px-0 text-center"
              sm={3}
              style={{ fontSize: "14px" }}
            >
              <Link
                to="/signup"
                style={{ textDecoration: "none", color: "inherit" }}
              >
                회원가입
              </Link>
            </Col>

            <Col
              className="px-0 text-center"
              sm={3}
              style={{ fontSize: "14px" }}
            >
              <Link
                to="/searchPw"
                style={{ textDecoration: "none", color: "inherit" }}
              >
                비밀번호 찾기
              </Link>
            </Col>
          </Row>
        </Container>

        <Container style={{ width: "400px" }}>
          <Row className="text-center mb-2">
            <Col>소셜 계정으로 간편 로그인</Col>
          </Row>
          <Row className="border-2 border-bottom"></Row>
          <Row className="d-flex justify-content-center mb-5">
            <img
              className="mt-4"
              src={require("../img/kakao.png")}
              style={{
                width: "70px",
                height: "50px",
                margintop: "0px",
                cursor: "pointer",
              }}
              alt="카카오아이콘"
              onClick={() => handleClickKakao("kakao")}
            />
            <img
              className="mt-4"
              src={require("../img/github_icon.png")}
              style={{
                width: "70px",
                height: "50px",
                margintop: "0px",
                cursor: "pointer",
              }}
              alt="github아이콘"
              onClick={() => handleClickGithub("github")}
            />
            <img
              className="mt-4"
              src={require("../img/naver.png")}
              style={{
                width: "70px",
                height: "50px",
                margintop: "0px",
                cursor: "pointer",
              }}
              alt="네이버아이콘"
              onClick={() => handleClickNaver("naver")}
            />
          </Row>
          <Row>
            <img
              className="mt-3 px-0"
              src="https://ssl.pstatic.net/melona/libs/1378/1378592/9baf2c4b14aec68ea800_20220902161708847.jpg"
              alt="네이버광고"
            />
          </Row>
        </Container>
      </div>
    </div>
  );
};

export default Login;
