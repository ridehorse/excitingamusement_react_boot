import React, { useEffect, useState } from "react";

import Container from "react-bootstrap/Container";
import Row from "react-bootstrap/Row";
import Col from "react-bootstrap/Col";

import "../css/searchPw.css";

const SignUpComplete = () => {
  const buttonStyle = {
    width: "60%",
    height: "50px",
    background: "#5a83c5",
    color: "#fff",
    fontSize: "20px",
    border: "none",
    borderRadius: "1px",
    cursor: "pointer",
  };

  function handleClick() {
    window.location.href = "/";
  }

  return (
    <div className="d-flex justify-content-center">
      <div style={{ width: "540px" }}>
        <Container>
          <Row
            style={{ marginTop: "90px" }}
            className="d-flex justify-content-center"
          >
            <img
              src={require("../img/signupComp.png")}
              alt="pwComplete"
              style={{ width: "400px" }}
            />
          </Row>
          <Row style={{ marginTop: "40px" }}>
            <div
              className="text-center"
              style={{ fontSize: "30px", fontWeight: "bold" }}
            >
              환영합니다!
            </div>
          </Row>
          <Row>
            <div
              className="text-center text-muted"
              style={{
                marginTop: "30px",
                fontSize: "17px",
                color: "#808080",
                fontWeight: "bold",
              }}
            >
              EXCITINGAMUSEMENT 가입이 완료 되었습니다.
            </div>
          </Row>
          <Row>
            <div
              className="text-center text-muted"
              style={{
                marginTop: "2px",
                fontSize: "17px",
                color: "#808080",
                fontWeight: "bold",
              }}
            >
              로그인을 하시면 다양한 컨텐츠를 이용하실 수 있습니다.
            </div>
          </Row>
         
          <Row
            className="d-flex justify-content-center"
            style={{ marginTop: "50px" }}
          >
            <input
              type="button"
              value="메인 화면으로"
              style={buttonStyle}
              onClick={handleClick}
            />
          </Row>
        </Container>
      </div>
    </div>
  );
};

export default SignUpComplete;
