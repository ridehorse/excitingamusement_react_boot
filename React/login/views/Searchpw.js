import React, { useState } from "react";

import Container from "react-bootstrap/Container";
import Row from "react-bootstrap/Row";
import Col from "react-bootstrap/Col";

import "../css/searchPw.css";
import { OverlayTrigger, Tooltip } from "react-bootstrap";
import { QuestionSquare } from "react-bootstrap-icons";
import { call } from "../service/ApiService";
import { CorrectMessage, ErrorMessage } from "../service/Messaging";

const SearchPw = () => {
  const tooltip = (
    <Tooltip id="tooltip" style={{ fontSize: "11px" }}>
      EXCITING AMUSEMENT가 발송한 메일이 스팸 메일로 분류된 것은 아닌지 확인해
      주세요. 스팸 메일함에도 메일이 없다면, 다시 한번 '인증번호 받기'를
      눌러주세요.
    </Tooltip>
  );

  const [memberId, setMemberId] = useState();
  const [email, setEmail] = useState();
  const [errorMessage, setErrorMessage] = useState("");
  const [correctMessage, setCorrectMessage] = useState("");
  const [messageName, setMessageName] = useState("");
  const [emailProp, setEmailProp] = useState(false);
  const [confirmNumber, setConfirmNumber] = useState("");
  const [userConfirm, setUserConfirm] = useState("");
  const [nextProp, setNextProp] = useState(true);

  function handleChangeMemberId(e) {
    setMemberId(e.target.value);
  }

  function handleChangeEmail(e) {
    setEmail(e.target.value);
  }

  function handleChangeUser(e) {
    setUserConfirm(e.target.value);
  }

  // 다음 키 누르면 아이디 session에 임시 저장
  function handleClickNext(e) {
    sessionStorage.setItem("TEMPO_ID", memberId);
    window.location.href = "/newPw";
  }

  function handleClickEmail(e) {
    setMessageName(e.target.name);
    setErrorMessage("");
    setCorrectMessage("");
    const request = {
      member_id: memberId,
      m_email: email,
    };
    // 인증번호 응답받는 동안 인증번호 버튼 비활성화
    setEmailProp(true);

    call("/email", "POST", request).then((response) => {
      if (response !== undefined) {
        setEmailProp(false);
        if (response === 1) {
          setErrorMessage("아이디에 등록되어있는 이메일을 입력해주세요.");
          setCorrectMessage("");
        } else {
          setCorrectMessage(
            "이메일이 전송되었습니다. 등록한 이메일을 확인해주세요."
          );
          console.log(response);
          setErrorMessage("");
          setConfirmNumber(response);
        }
      }

      // controller에서 badREquest로 보내면(400응답받으면 response가 undefined로 온다.)
      if (response === undefined) {
        setErrorMessage("올바른 아이디를 입력해주세요.");
        setCorrectMessage("");
      }
    });
  }

  function handleClickConfirm(e) {
    console.log(confirmNumber);
    console.log(userConfirm);
    setMessageName(e.target.name);
    if (
      confirmNumber !== "" &&
      confirmNumber.toString() === userConfirm.toString()
    ) {
      setCorrectMessage("인증번호가 일치합니다. 다음버튼을 눌러주세요.");
      setErrorMessage("");
      setNextProp(false);
    } else {
      setErrorMessage("인증번호가 일치하지 않습니다.");
      setCorrectMessage("");
    }
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
                비밀번호 찾기
              </div>
            </Col>
            <Col sm={9} className="text-center">
              <div>
                <span style={{ fontSize: "15px", color: "green" }}>
                  01.본인 확인{" "}
                </span>
                &gt;
                <span style={{ fontSize: "15px" }}> 02. 비밀번호 재설정 </span>
                &gt;
                <span style={{ fontSize: "15px" }}> 03. 변경 완료</span>
              </div>
            </Col>
          </Row>

          <Row style={{ marginTop: "70px" }}>
            <Col sm={1}>
              <input type="radio" checked readOnly />
            </Col>
            <Col style={{ fontSize: "17px", fontWeight: "550" }}>
              회원정보에 등록한 휴대전화로 인증
            </Col>
          </Row>
          <Row style={{ marginBottom: "80px" }}>
            <Col sm={1}></Col>
            <Col
              className="text-muted"
              style={{ fontSize: "13px", fontWeight: "400" }}
            >
              회원정보에 등록한 휴대전화 번호와 입력한 휴대전화 번호가 같아야,
              인증번호를 받을 수 있습니다.
            </Col>
          </Row>
          <Row className="mb-3">
            <Col sm={1}></Col>
            <Col sm={3} style={{ fontSize: "15px", fontWeight: "550" }}>
              아이디
            </Col>
            <Col sm={5} className="px-0">
              <input
                type="text"
                onChange={handleChangeMemberId}
                style={{ width: "160px", height: "24px" }}
                name="member_id"
              />
            </Col>
          </Row>
          <Row>
            <Col sm={1}></Col>
            <Col sm={3} style={{ fontSize: "15px", fontWeight: "550" }}>
              이메일 주소
            </Col>
            <Col sm={5} className="px-0">
              <input
                type="text"
                onChange={handleChangeEmail}
                style={{ width: "220px", height: "24px" }}
                name="m_email"
              />
            </Col>
            <Col sm={2} className="mx-3">
              <input
                className="border-info"
                type="button"
                value="인증번호"
                style={{ width: "80px", fontSize: "13px", height: "25px" }}
                onClick={handleClickEmail}
                disabled={emailProp}
                name="confirmNumber"
              />
            </Col>
          </Row>
          <div style={{ paddingLeft: "44px" }}>
            {messageName === "confirmNumber" ? (
              <ErrorMessage errorMessage={errorMessage} />
            ) : null}
            {messageName === "confirmNumber" ? (
              <CorrectMessage correctMessage={correctMessage} />
            ) : null}
          </div>
          <Row className="mb-2 mt-3">
            <Col sm={1}></Col>
            <Col sm={3}></Col>
            <Col sm={5} className="px-0">
              <input
                type="text"
                onChange={handleChangeUser}
                style={{ width: "220px", height: "24px" }}
              />
            </Col>
            <Col sm={2} className="mx-3">
              <input
                className="border-info"
                type="button"
                value="확인"
                style={{
                  width: "80px",
                  fontSize: "13px",
                  height: "25px",
                }}
                name="confirm"
                onClick={handleClickConfirm}
              />
            </Col>
          </Row>
          <Row>
            <Col sm={1}></Col>
            <Col sm={3}></Col>
            <Col
              sm={8}
              className="text-muted px-0"
              style={{ fontSize: "12px" }}
            >
              인증번호가 오지 않나요{" "}
              <OverlayTrigger placement="bottom" overlay={tooltip}>
                <QuestionSquare />
              </OverlayTrigger>
            </Col>
          </Row>
          <div style={{ marginLeft: "45px" }}>
            {messageName === "confirm" ? (
              <ErrorMessage errorMessage={errorMessage} />
            ) : null}
            {messageName === "confirm" ? (
              <CorrectMessage correctMessage={correctMessage} />
            ) : null}
          </div>
          <Row style={{ marginTop: "100px" }}>
            <Col className="d-flex justify-content-center">
              <input
                className="border-info"
                type="button"
                value="다음"
                style={{ width: "100px", fontSize: "15px", height: "29px" }}
                name="next"
                disabled={nextProp}
                onClick={handleClickNext}
              />
            </Col>
          </Row>
        </Container>
      </div>
    </div>
  );
};

export default SearchPw;
