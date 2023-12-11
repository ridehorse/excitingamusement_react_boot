import React, { useState } from "react";

import Container from "react-bootstrap/Container";
import Row from "react-bootstrap/Row";
import Col from "react-bootstrap/Col";

import "../css/searchPw.css";
import { OverlayTrigger, Tooltip } from "react-bootstrap";
import { CorrectMessage, ErrorMessage } from "../service/Messaging";
import { call } from "../service/ApiService";

const NewPw = () => {
  const tooltip = (
    <Tooltip id="tooltip" style={{ fontSize: "11px" }}>
      EXCITING AMUSEMENT가 발송한 메일이 스팸 메일로 분류된 것은 아닌지 확인해
      주세요. 스팸 메일함에도 메일이 없다면, 다시 한번 '인증번호 받기'를
      눌러주세요.
    </Tooltip>
  );

  const member_id = sessionStorage.getItem("TEMPO_ID");

  const [pass, setPass] = useState("");
  const [pass2, setPass2] = useState("");
  const [errorMessage, setErrorMessage] = useState("");
  const [correctMessage, setCorrectMessage] = useState("");
  const [possible, setPossible] = useState(true);
  const [messageName, setMessageName] = useState("");

  let inputName = "";
  let inputValue = "";
  function handleChangeInput(e) {
    inputName = e.target.name;
    inputValue = e.target.value;
    console.log("name : " + inputName);
    console.log("pass : " + pass);
    console.log("pass2 : " + pass2);
    if (inputName === "m_pass") {
      setPass(inputValue);
      setMessageName(inputName);
      setCorrectMessage("");
      setErrorMessage("");
      if (
        !/^(?=.*[a-zA-Zㄱ-힣])(?=.*\d)(?=.*[~`!@#$%\^&*\(\)\-_=+\\\|\[\]\{\};:'",<.>\/?]).{8,}$/.test(
          pass
        )
      ) {
        setErrorMessage(
          "비밀번호는 한글,영문,특수문자 포함 8글자 이상이어야 합니다."
        );
        setCorrectMessage("");
        setPossible(true);
      } else if (
        /^(?=.*[a-zA-Zㄱ-힣])(?=.*\d)(?=.*[~`!@#$%\^&*\(\)\-_=+\\\|\[\]\{\};:'",<.>\/?]).{8,}$/.test(
          pass
        )
      ) {
        setCorrectMessage("가능한 비밀번호 입니다.");
        setErrorMessage("");
        setPossible(true);
      }
    }

    if (inputName === "m_pass2") {
      setPass2(inputValue);
      setMessageName(inputName);
      setCorrectMessage("");
      setErrorMessage("");
      if (
        /^(?=.*[a-zA-Zㄱ-힣])(?=.*\d)(?=.*[~`!@#$%\^&*\(\)\-_=+\\\|\[\]\{\};:'",<.>\/?]).{8,}$/.test(
          pass
        ) &&
        pass !== inputValue
      ) {
        setCorrectMessage("");
        setErrorMessage("비밀번호가 일치하지 않습니다.");
        setPossible(true);
      } else if (
        /^(?=.*[a-zA-Zㄱ-힣])(?=.*\d)(?=.*[~`!@#$%\^&*\(\)\-_=+\\\|\[\]\{\};:'",<.>\/?]).{8,}$/.test(
          pass
        ) &&
        pass === inputValue
      ) {
        setCorrectMessage("비밀번호가 일치합니다.");
        setPossible(false);
      }
    }
  }
  function handleClickNext(e) {
    const request = {
      member_id: sessionStorage.getItem("TEMPO_ID"),
      m_pass: pass,
    };
    call("/login/newPw", "POST", request).then((response) => {
      if (response === 1) {
        console.log("비밀번호 수정 성공");
        sessionStorage.removeItem("TEMPO_ID");
        window.location.href = "/pwComplete";
      } else {
        console.log("비밀번호 수정 실패");
      }
    });
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
                비밀번호 재설정
              </div>
            </Col>
            <Col sm={9} className="text-center">
              <div>
                <span style={{ fontSize: "15px" }}>01.본인 확인 </span>
                &gt;
                <span style={{ fontSize: "15px", color: "green" }}>
                  {" "}
                  02. 비밀번호 재설정{" "}
                </span>
                &gt;
                <span style={{ fontSize: "15px" }}> 03. 변경 완료</span>
              </div>
            </Col>
          </Row>

          <Row style={{ marginTop: "10px" }}>
            <Col className="text-muted" style={{ fontSize: "14px" }}>
              비밀번호를 변경해주세요.
            </Col>
          </Row>
          <Row style={{ marginBottom: "50px" }}>
            <Col
              className="text-muted"
              style={{ fontSize: "14px", fontWeight: "400" }}
            >
              다른 아이디나 사이트에서 사용한 적 없는 안전한 비밀번호로 변경해
              주세요.
            </Col>
          </Row>
        </Container>
        <Container className="border-1 border" style={{ width: "490px" }}>
          <Row style={{ marginTop: "70px" }}>
            <Col sm={3}></Col>
            <Col sm={7} className="border-bottom pb-1">
              <span style={{ fontWeight: "550" }}>아이디</span> :{" "}
              <span style={{ color: "green" }}>{member_id}</span>
            </Col>
          </Row>
          <Row style={{ marginTop: "70px" }}>
            <Col sm={3} style={{ width: "100px" }}></Col>
            <Col sm={4} style={{ fontWeight: "550", fontSize: "15px" }}>
              새 비밀번호
            </Col>
            <Col sm={4} style={{ fontWeight: "550" }} className="px-0">
              <input
                type="text"
                style={{ width: "130px", height: "24px" }}
                onChange={handleChangeInput}
                name="m_pass"
              ></input>
            </Col>
          </Row>
          <div style={{ marginLeft: "80px" }}>
            {messageName === "m_pass" ? (
              <ErrorMessage errorMessage={errorMessage} />
            ) : null}
            {messageName === "m_pass" ? (
              <CorrectMessage correctMessage={correctMessage} />
            ) : null}
          </div>
          <Row style={{ marginTop: "20px" }}>
            <Col sm={3} style={{ width: "100px" }}></Col>
            <Col sm={4} style={{ fontWeight: "550", fontSize: "15px" }}>
              비밀번호 확인
            </Col>
            <Col sm={4} style={{ fontWeight: "550" }} className="px-0">
              <input
                type="text"
                style={{ width: "130px", height: "24px" }}
                name="m_pass2"
                onChange={handleChangeInput}
              ></input>
            </Col>
          </Row>
          <div style={{ marginLeft: "80px" }}>
            {messageName === "m_pass2" ? (
              <ErrorMessage errorMessage={errorMessage} />
            ) : null}
            {messageName === "m_pass2" ? (
              <CorrectMessage correctMessage={correctMessage} />
            ) : null}
          </div>
          <Row style={{ marginBottom: "50px", marginTop: "50px" }}>
            <Col className="d-flex justify-content-center">
              <input
                type="button"
                className="border-info"
                style={{ width: "120px", fontSize: "15px", height: "29px" }}
                value="비밀번호 변경"
                disabled={possible}
                name="next"
                onClick={handleClickNext}
              ></input>
            </Col>
          </Row>
          <Row style={{ marginTop: "50px" }}>
            <Col sm={1}></Col>
            <Col sm={10} className="border-1 border"></Col>
            <Col sm={1}></Col>
          </Row>
          <Row style={{ marginTop: "40px" }}>
            <Col sm={1}></Col>
            <Col className="text-muted" style={{ fontSize: "13px" }}>
              *영문,숫자,특수문자를 함께 사용하면 보다 안전합니다.
            </Col>
            <Col sm={1}></Col>
          </Row>
          <Row style={{ marginBottom: "30px" }}>
            <Col sm={1}></Col>
            <Col className="text-muted" style={{ fontSize: "13px" }}>
              *다른 서비스와 다른 EXCITING AMUSEMENT만의 비밀번호를
              만들어주세요.
            </Col>
            <Col sm={1}></Col>
          </Row>
        </Container>
      </div>
    </div>
  );
};

export default NewPw;
