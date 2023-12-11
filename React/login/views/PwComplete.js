import React, { useState } from "react";

import Container from "react-bootstrap/Container";
import Row from "react-bootstrap/Row";
import Col from "react-bootstrap/Col";

import "../css/searchPw.css";

const PwComplete = () => {
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
    window.location.href = "/login";
  }

  return (
    <div className="d-flex justify-content-center">
      <div style={{ width: "540px" }}>
        <Container>
          <Row style={{ marginTop: "80px" }} className="border-bottom border-1">
            <Col sm={3}>
              <div
                className="pb-1 border-bottom border-2 border-success text-center"
                style={{ fontSize: "15px" }}
              >
                변경 완료
              </div>
            </Col>
            <Col sm={9} className="text-center">
              <div>
                <span style={{ fontSize: "15px" }}>01.본인 확인 </span>
                &gt;
                <span style={{ fontSize: "15px" }}> 02. 비밀번호 재설정 </span>
                &gt;
                <span style={{ fontSize: "15px", color: "green" }}>
                  {" "}
                  03. 변경 완료
                </span>
              </div>
            </Col>
          </Row>
          <Row
            style={{ marginTop: "30px" }}
            className="d-flex justify-content-center"
          >
            <img
              src={require("../img/keykey.png")}
              alt="pwComplete"
              style={{ width: "400px" }}
            />
          </Row>
          <Row style={{ marginTop: "40px" }}>
            <div
              className="text-center"
              style={{ fontSize: "20px", fontWeight: "bold" }}
            >
              비밀번호 변경 완료
            </div>
          </Row>
          <Row>
            <div
              className="text-center text-muted"
              style={{
                marginTop: "30px",
                fontSize: "14px",
                color: "#808080",
                fontWeight: "bold",
              }}
            >
              비밀번호 변경이 완료 되었습니다.
            </div>
          </Row>
          <Row>
            <div
              className="text-center text-muted"
              style={{
                marginTop: "2px",
                fontSize: "14px",
                color: "#808080",
                fontWeight: "bold",
              }}
            >
              새로운 비밀번호로 로그인 해주세요.
            </div>
          </Row>
          <Row
            className="d-flex justify-content-center"
            style={{ marginTop: "30px" }}
          >
            <input
              type="button"
              value="로그인 화면으로"
              style={buttonStyle}
              onClick={handleClick}
            />
          </Row>
        </Container>
      </div>
    </div>
  );
};

export default PwComplete;
