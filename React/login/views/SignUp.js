import React, { useEffect, useRef, useState } from "react";

import "../css/signup.css";

import { useDaumPostcodePopup } from "react-daum-postcode";
import Container from "react-bootstrap/Container";
import Row from "react-bootstrap/Row";
import Col from "react-bootstrap/Col";
import { call } from "../service/ApiService";
import { CorrectMessage, ErrorMessage } from "../service/Messaging";

const SignUp = () => {
  // form tag 정보 저장
  const formRef = useRef(null);

  // kakao_id값 hidden 에 저장(kakao_id가 없으면 false로 저장)
  // git_id값 hidden 에 저장(git_id가 없으면 false로 저장)
  const [kakaoId, setKakaoId] = useState("false");
  const [gitId, setGitId] = useState("false");
  const [naverId, setNaverId] = useState("false");

  useEffect(() => {
    if (sessionStorage.getItem("KAKAO_ID") !== null) {
      setKakaoId(sessionStorage.getItem("KAKAO_ID"));

      console.log("signUp/kakao_id : " + kakaoId);
    }

    if (sessionStorage.getItem("GIT_ID") !== null) {
      setGitId(sessionStorage.getItem("GIT_ID"));

      console.log("signUp/git_id : " + gitId);
    }

    if (sessionStorage.getItem("NAVER_ID") !== null) {
      setNaverId(sessionStorage.getItem("NAVER_ID"));

      console.log("signUp/naver_id : " + naverId);
    }

    const currentParams = new URLSearchParams(window.location.search);
    if (currentParams.get("kakao_id")) {
      setKakaoId(currentParams.get("kakao_id"));
    }

    const currentParams2 = new URLSearchParams(window.location.search);
    if (currentParams2.get("gid_id")) {
      setGitId(currentParams2.get("gid_id"));
    }

    const currentParams3 = new URLSearchParams(window.location.search);
    if (currentParams3.get("naver_id")) {
      setNaverId(currentParams3.get("naver_id"));
    }
  }, []);

  const trunNaverId = naverId.substring(0, 13);

  const [errorMessage, setErrorMessage] = useState("");
  const [correctMessage, setCorrectMessage] = useState("");

  const [errorName, setErrorName] = useState("");
  const [formValue, setFormValue] = useState("");
  const [enableSubmit, setEnableSubmit] = useState("");
  const [passValue, setPassValue] = useState("");

  // 카카오,git 로그인시 랜덤 비밀번호 생성
  const [randomPass, setRandomPass] = useState("");
  useEffect(() => {
    const characters =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    let result = "";
    for (let i = 0; i < 10; i++) {
      const randomIndex = Math.floor(Math.random() * characters.length);
      result += characters.charAt(randomIndex);
    }
    setRandomPass(result);
  }, []);
  // 랜덤 비밀번호 끝

  function handleBlur(e) {
    const { name, value } = e.target;
    setErrorName(name);
    setEnableSubmit("false");
    setFormValue(value);
    setErrorMessage("");

    console.log("signup/name : " + name);

    if (name === "member_id" && value.length < 5) {
      setErrorMessage("아이디는 5글자 이상이어야 합니다.");
      return;
    } else if (name === "member_id") {
      // 유효성 검사 통과하면 사용자가 적은 ID가 DB에 있는지 없는지 확인
      const request = { member_id: value };
      call("/login/matchId", "POST", request).then((response) => {
        if (response) {
          setErrorMessage("이미 등록된 아이디 입니다.");
          setCorrectMessage("");
          return;
        } else {
          setErrorMessage("");
          setCorrectMessage("사용가능한 아이디 입니다.");
        }
      });
    }

    if (
      name === "m_pass" &&
      !/^(?=.*[a-zA-Zㄱ-힣])(?=.*\d)(?=.*[~`!@#$%\^&*\(\)\-_=+\\\|\[\]\{\};:'",<.>\/?]).{8,}$/.test(
        value
      )
    ) {
      setErrorMessage(
        "비밀번호는 한글,영문,특수문자 포함해서 8글자 이상입니다."
      );
      setCorrectMessage("");
      setPassValue(value);
      return;
    } else if (name === "m_pass") {
      setPassValue(value);
      setErrorMessage("");
      setCorrectMessage("사용가능한 비밀번호 입니다.");
    }

    if (name === "m_pass2" && value !== passValue) {
      setErrorMessage("비밀번호가 일치하지 않습니다.");
      setCorrectMessage("");
      return;
    } else if (name === "m_pass2") {
      setCorrectMessage("비밀번호가 일치 합니다.");
      setErrorMessage("");
    }

    if (name === "m_name" && /^^[^가-힣]*$/.test(value)) {
      setErrorMessage("이름은 한글이어야 합니다.");
      setCorrectMessage("");
      return;
    } else if (name === "m_name") {
      setErrorMessage("");
    }

    if (name === "year" && !/^(19[0-9]{2}|20[0-2][0-3])$/.test(value)) {
      setErrorMessage("유효한 나이를 입력해주세요.");
      setCorrectMessage("");
      return;
    } else if (name === "year") {
      setErrorMessage("");
    }

    // 잘못된 입력 없이 여기까지 오면 true로 상태 변환(true이면 submit 가능)
    setEnableSubmit("true");
  }

  // 이메일 값 클릭
  function handleEmailClick(e) {
    formRef.current.querySelector("#email2").value = e.target.value;
  }

  //  주소찾기 용 함수
  const open = useDaumPostcodePopup();

  //   콜백함수 정의
  const handleComplete = (data) => {
    let fullAddress = data.address;
    let extraAddress = "";

    if (data.addressType === "R") {
      if (data.bname !== "") {
        extraAddress += data.bname;
      }
      if (data.buildingName !== "") {
        extraAddress +=
          extraAddress !== "" ? `, ${data.buildingName}` : data.buildingName;
      }
      fullAddress += extraAddress !== "" ? ` (${extraAddress})` : "";
    }

    console.log("zoncode : " + data.zonecode);
    console.log("bname : " + data.bname);
    console.log("buildingName : " + data.buildingName);
    console.log("extraAddress : " + extraAddress);
    console.log("fullAddress : " + fullAddress); // e.g. '서울 성동구 왕십리로2길 20 (성수동1가)'
    console.log(formRef.current.querySelector("#m_address2").value);
    formRef.current.querySelector("#m_address2").value = fullAddress;
    formRef.current.querySelector("#m_address1").value = data.zonecode;
  };

  function handleClickJuso() {
    open({ onComplete: handleComplete });
  }

  // 가입하기 버튼 클릭 이벤트
  function handleClick() {
    setErrorMessage("");

    // kakaoID 로그
    const kakao_id = formRef.current.querySelector("#hidden").value;
    console.log(kakao_id);
    const git_id = formRef.current.querySelector("#hidden2").value;
    console.log(git_id);
    const naver_id = formRef.current.querySelector("#hidden3").value;
    console.log(naver_id);
    const member_id = formRef.current.querySelector("#member_id").value;

    const m_pass = formRef.current.querySelector("#m_pass").value;
    const m_pass2 = formRef.current.querySelector("#m_pass2").value;

    const m_name = formRef.current.querySelector("#m_name").value;

    const year = formRef.current.querySelector("#year").value;
    const month = formRef.current.querySelector("#month").value;
    const day = formRef.current.querySelector("#day").value;

    const m_phone1 = formRef.current.querySelector("#m_phone1").value;
    const m_phone2 = formRef.current.querySelector("#m_phone2").value;
    const m_phone3 = formRef.current.querySelector("#m_phone3").value;

    const m_phone = m_phone1 + m_phone2 + m_phone3;

    const m_address1 = formRef.current.querySelector("#m_address1").value;
    const m_address2 = formRef.current.querySelector("#m_address2").value;
    const m_address3 = formRef.current.querySelector("#m_address3").value;

    const m_address = m_address1 + "/" + m_address2 + " " + m_address3;

    const email1 = formRef.current.querySelector("#email1").value;
    const email2 = formRef.current.querySelector("#email2").value;

    const m_gender = formRef.current.querySelector("#m_gender").value;

    console.log(member_id);
    console.log(formRef.current);

    const m_birth = year + month + day;
    const m_email = email1 + "@" + email2;

    // 가입하기 버튼 눌렀을때 공백 유효성 검사
    if (member_id === null || member_id === "") {
      setErrorName(formRef.current.querySelector("#member_id").name);
      setErrorMessage("아이디를 입력해주세요.");
      return;
    }
    if (m_pass === null || m_pass === "") {
      setErrorName(formRef.current.querySelector("#m_pass").name);
      setErrorMessage("비밀번호를 입력해주세요.");
      return;
    }
    if (m_pass2 === null || m_pass2 === "") {
      setErrorName(formRef.current.querySelector("#m_pass2").name);
      setErrorMessage("비밀번호 확인을 입력해주세요.");
      return;
    }
    if (m_name === null || m_name === "") {
      setErrorName(formRef.current.querySelector("#m_name").name);
      setErrorMessage("이름을 입력해주세요.");
      return;
    }
    if (year === null || year === "") {
      setErrorName(formRef.current.querySelector("#year").name);
      setErrorMessage("년도를 입력해주세요.");
      return;
    }
    if (month === "") {
      setErrorName(formRef.current.querySelector("#month").name);
      setErrorMessage("월을 입력해주세요.");
      return;
    }
    if (day === "" || day === null) {
      setErrorName(formRef.current.querySelector("#month").name);
      setErrorMessage("날짜를 입력해주세요.");
      return;
    }
    if (m_gender === "") {
      setErrorName(formRef.current.querySelector("#m_gender").name);
      setErrorMessage("성별을 입력해주세요.");
      return;
    }
    if (email1 === null || email1 === "") {
      setErrorName(formRef.current.querySelector("#email1").name);
      setErrorMessage("이메일을 입력해주세요.");
      return;
    }
    if (email2 === null || email2 === "") {
      setErrorName(formRef.current.querySelector("#email2").name);
      setErrorMessage("이메일을 입력해주세요.");
      return;
    }
    if (m_address2 === null || m_address2 === "") {
      setErrorName(formRef.current.querySelector("#m_address3").name);
      setErrorMessage("주소를 입력해주세요.");
      return;
    }
    if (m_phone1 === null || m_phone1 === "") {
      setErrorName(formRef.current.querySelector("#m_phone1").name);
      setErrorMessage("전화번호를 입력해주세요.");
      return;
    }
    if (m_phone2 === null || m_phone2 === "") {
      setErrorName(formRef.current.querySelector("#m_phone1").name);
      setErrorMessage("전화번호를 입력해주세요.");
      return;
    }
    if (m_phone3 === null || m_phone3 === "") {
      setErrorName(formRef.current.querySelector("#m_phone1").name);
      setErrorMessage("전화번호를 입력해주세요.");
      return;
    }

    const param = {
      member_id: member_id,
      m_pass: m_pass,
      m_name: m_name,
      m_birth: m_birth,
      m_email: m_email,
      m_phone: m_phone,
      m_address: m_address,
      m_gender: m_gender,
      m_kakao_id: kakao_id,
      m_github_id: git_id,
      m_naver_id: naver_id,
    };

    console.log(param);

    if (enableSubmit === "true") {
      call("/login/signup", "POST", param).then((response) => {
        console.log("응답받음");
        window.location.href = "/signUpComplete";
      });
    }
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
          {kakaoId === "false" ? (
            gitId === "false" ? (
              naverId === "false" ? (
              ""
              ) : (
                <Row
                className="p-4 mx-2 border-1 border border-success text-center"
                style={{ marginTop: "20px", marginBottom: "30px" }}
              >
                <div style={{ fontWeight: "bold" }}>
                  첫 1회 로그인시에는 EXCITINGAMUSEMENT의 컨텐츠를 이용하기 위한
                  정보입력이 필요합니다.
                </div>
              </Row>
              )
            ) : (
              <Row
                className="p-4 mx-2 border-1 border border-success text-center"
                style={{ marginTop: "20px", marginBottom: "30px" }}
              >
                <div style={{ fontWeight: "bold" }}>
                  첫 1회 로그인시에는 EXCITINGAMUSEMENT의 컨텐츠를 이용하기 위한
                  정보입력이 필요합니다.
                </div>
              </Row>
            )
          ) : (
            <Row
              className="p-4 mx-2 border-1 border border-success text-center"
              style={{ marginTop: "20px", marginBottom: "30px" }}
            >
              <div style={{ fontWeight: "bold" }}>
                첫 1회 로그인시에는 EXCITINGAMUSEMENT의 컨텐츠를 이용하기 위한
                정보입력이 필요합니다.
              </div>
            </Row>
          )}
        </Container>

        <Container>
          <form ref={formRef}>
            {/* kakaoid 존재여부 저장 */}
            <input type="hidden" id="hidden" name="hidden" value={kakaoId} />
            {/* gitid 존재여부 저장 */}
            <input type="hidden" id="hidden2" name="hidden2" value={gitId} />
            {/* naverid 존재여부 저장 */}
            <input type="hidden" id="hidden3" name="hidden3" value={naverId} />
            {/* 아이디 */}
            {kakaoId === "false" ? (
              gitId === "false" ? (
                naverId === "false" ? (
                <div className="mb-4">
                  <Row className="mb-2">
                    <div className="signup-text">아이디</div>
                  </Row>
                  <Row className="px-2">
                    <div className="signup-input">
                      <input
                        id="member_id"
                        type="text"
                        name="member_id"
                        className="border-0"
                        style={{ outline: "none", width: "100%" }}
                        onBlur={handleBlur}
                      ></input>
                    </div>
                  </Row>
                  {errorName === "member_id" ? (
                    <ErrorMessage errorMessage={errorMessage} />
                  ) : null}
                  {errorName === "member_id" ? (
                    <CorrectMessage correctMessage={correctMessage} />
                  ) : null}
                </div>
                ) : (
                  <input
                  type="hidden"
                  id="member_id"
                  name="member_id"
                  value={`naver_${trunNaverId}`}
                />
                )
              ) : (
                <input
                  type="hidden"
                  id="member_id"
                  name="member_id"
                  value={`github_${gitId}`}
                />
              )
            ) : (
              <input
                type="hidden"
                id="member_id"
                name="member_id"
                value={`kakao_${kakaoId}`}
              />
            )}

            {/* 비밀번호 */}
            {kakaoId === "false" ? (
              gitId === "false" ? (
                naverId === "false" ? (
                <div className="mb-4">
                  <Row className="mb-2">
                    <div className="signup-text">비밀번호</div>
                  </Row>
                  <Row className="px-2">
                    <div className="signup-input">
                      <input
                        id="m_pass"
                        type="password"
                        name="m_pass"
                        className="border-0"
                        style={{ outline: "none", width: "100%" }}
                        onBlur={handleBlur}
                      ></input>
                    </div>
                  </Row>
                  {errorName === "m_pass" ? (
                    <ErrorMessage errorMessage={errorMessage} />
                  ) : null}
                  {errorName === "m_pass" ? (
                    <CorrectMessage correctMessage={correctMessage} />
                  ) : null}{" "}
                </div>
                ):(
                  <input
                  type="hidden"
                  id="m_pass"
                  name="m_pass"
                  value={randomPass}
                />
                )
              ) : (
                <input
                  type="hidden"
                  id="m_pass"
                  name="m_pass"
                  value={randomPass}
                />
              )
            ) : (
              <input
                type="hidden"
                id="m_pass"
                name="m_pass"
                value={randomPass}
              />
            )}

            {/* 비밀번호 확인 */}
            {kakaoId === "false" ? (
              gitId === "false" ? (
                naverId === "false" ? (
                <div className="mb-4">
                  <Row className="mb-2">
                    <div className="signup-text">비밀번호 확인</div>
                  </Row>
                  <Row className="px-2">
                    <div className="signup-input">
                      <input
                        id="m_pass2"
                        type="password"
                        name="m_pass2"
                        className="border-0"
                        style={{ outline: "none", width: "100%" }}
                        onBlur={handleBlur}
                      ></input>
                    </div>
                  </Row>
                  {errorName === "m_pass2" ? (
                    <ErrorMessage errorMessage={errorMessage} />
                  ) : null}
                  {errorName === "m_pass2" ? (
                    <CorrectMessage correctMessage={correctMessage} />
                  ) : null}{" "}
                </div>
                ) : (
                  <input
                  type="hidden"
                  id="m_pass2"
                  name="m_pass2"
                  value={randomPass}
                />
                )
              ) : (
                <input
                  type="hidden"
                  id="m_pass2"
                  name="m_pass2"
                  value={randomPass}
                />
              )
            ) : (
              <input
                type="hidden"
                id="m_pass2"
                name="m_pass2"
                value={randomPass}
              />
            )}

            {/* 이름 */}
            <div className="mb-4">
              <Row className="mb-2">
                <div className="signup-text">이름</div>
              </Row>
              <Row className="px-2">
                <div className="signup-input">
                  <input
                    id="m_name"
                    type="text"
                    name="m_name"
                    className="border-0"
                    style={{ outline: "none", width: "100%" }}
                    onBlur={handleBlur}
                  ></input>
                </div>
              </Row>
              {errorName === "m_name" ? (
                <ErrorMessage errorMessage={errorMessage} />
              ) : null}
            </div>

            {/* 생년월일 */}
            <div className="mb-4">
              <Row className="mb-2">
                <div className="signup-text">생년월일</div>
              </Row>
              <Row className="px-2">
                <Col className="px-0">
                  <div className="signup-input">
                    <input
                      id="year"
                      type="text"
                      name="year"
                      className="border-0"
                      style={{ outline: "none", width: "100%" }}
                      placeholder="년(4자)"
                      onBlur={handleBlur}
                    ></input>
                  </div>
                </Col>
                <Col className="mx-1">
                  <div className="signup-input">
                    <select
                      id="month"
                      className="border-0 selectbox"
                      name="month"
                      style={{ outline: "none", width: "100%" }}
                    >
                      <option value="">월</option>
                      <option value="1">01</option>
                      <option value="2">02</option>
                      <option value="3">03</option>
                      <option value="4">04</option>
                      <option value="5">05</option>
                      <option value="6">06</option>
                      <option value="7">07</option>
                      <option value="8">08</option>
                      <option value="9">09</option>
                      <option value="10">10</option>
                      <option value="11">11</option>
                      <option value="12">12</option>
                    </select>
                  </div>
                </Col>
                <Col className="px-0">
                  <div className="signup-input">
                    <input
                      id="day"
                      type="text"
                      className="border-0 day"
                      style={{ outline: "none", width: "100%" }}
                      placeholder="일"
                      onBlur={handleBlur}
                    ></input>
                  </div>
                </Col>
              </Row>
              {errorName === "year" ||
              errorName === "month" ||
              errorName === "day" ? (
                <ErrorMessage errorMessage={errorMessage} />
              ) : null}
            </div>

            {/* 성별 */}
            <div className="mb-4">
              <Row className="mb-2">
                <div className="signup-text">성별</div>
              </Row>
              <Row className="px-2">
                <div className="signup-input">
                  <select
                    id="m_gender"
                    name="m_gender"
                    className="border-0 selectbox"
                    style={{ outline: "none", width: "100%" }}
                  >
                    <option value="">성별</option>
                    <option value="man">남자</option>
                    <option value="woman">여자</option>
                  </select>
                </div>
              </Row>
              {errorName === "m_gender" ? (
                <ErrorMessage errorMessage={errorMessage} />
              ) : null}
            </div>

            {/* 이메일 */}
            <div className="mb-4">
              <Row className="mb-2">
                <div className="signup-text">이메일</div>
              </Row>
              <Row>
                <Col sm={4}>
                  <div className="signup-input">
                    <input
                      id="email1"
                      type="text"
                      name="email1"
                      className="border-0"
                      style={{ outline: "none", width: "100%" }}
                      onBlur={handleBlur}
                    ></input>
                  </div>
                </Col>
                <Col sm={1} className="pt-2">
                  @
                </Col>
                <Col sm={4}>
                  <div className="signup-input">
                    <input
                      id="email2"
                      type="text"
                      name="email2"
                      className="border-0"
                      style={{ outline: "none", width: "100%" }}
                      onBlur={handleBlur}
                    ></input>
                  </div>
                </Col>
                <Col sm={3}>
                  <div className="signup-input">
                    <select
                      onClick={handleEmailClick}
                      id="email3"
                      name="email3"
                      className="border-0 selectbox"
                      style={{ outline: "none", width: "100%" }}
                    >
                      <option value="">직접입력</option>
                      <option value="naver.com">naver.com</option>
                      <option value="daum.net">daum.net</option>
                      <option value="gmail.com">gmail.com</option>
                    </select>
                  </div>
                </Col>
              </Row>
              {errorName === "email1" || errorName === "email2" ? (
                <ErrorMessage errorMessage={errorMessage} />
              ) : null}
            </div>

            {/* 주소 */}
            <div className="mb-4">
              <Row className="mb-2">
                <div className="signup-text">주소</div>
              </Row>
              <Row className="px-2">
                <Col sm={3} className="px-0">
                  <div className="signup-input">
                    <input
                      id="m_address1"
                      type="text"
                      name="m_address1"
                      className="border-0"
                      style={{ outline: "none", width: "100%" }}
                      placeholder="우편번호"
                      onBlur={handleBlur}
                      readOnly
                    ></input>
                  </div>
                </Col>

                <Col sm={3}>
                  <div>
                    <input
                      type="button"
                      id="jusoBtn"
                      value="주소찾기"
                      className="ms-2 mt-1 py-2 border border-info"
                      style={{ width: "100%", height: "40px" }}
                      onClick={handleClickJuso}
                    />
                  </div>
                </Col>
              </Row>
              <Row className="px-2">
                <Col sm={12} className="px-0 mt-2">
                  <div className="signup-input">
                    <input
                      id="m_address2"
                      type="text"
                      name="m_address2"
                      className="border-0"
                      style={{ outline: "none", width: "100%" }}
                      placeholder="주소"
                      onBlur={handleBlur}
                      readOnly
                    ></input>
                  </div>
                </Col>
              </Row>
              <Row className="px-2">
                <Col sm={12} className="px-0 mt-2">
                  <div className="signup-input">
                    <input
                      id="m_address3"
                      type="text"
                      name="m_address3"
                      className="border-0"
                      style={{ outline: "none", width: "100%" }}
                      placeholder="상세주소"
                      onBlur={handleBlur}
                    ></input>
                  </div>
                </Col>
              </Row>
              {errorName === "m_address3" ? (
                <ErrorMessage errorMessage={errorMessage} />
              ) : null}
            </div>

            {/* 휴대전화 */}
            <div className="mb-4">
              <Row className="mb-2">
                <div className="signup-text">휴대전화</div>
              </Row>
              <Row className="px-2">
                <Col sm={2} className="px-0">
                  <div className="signup-input" style={{ width: "100px" }}>
                    <input
                      id="m_phone1"
                      type="text"
                      name="m_phone1"
                      className="border-0"
                      style={{ outline: "none", width: "100%" }}
                      placeholder="010"
                      onBlur={handleBlur}
                    ></input>
                  </div>
                </Col>
                <Col sm={4} className="px-0" style={{ marginLeft: "47px" }}>
                  <div className="signup-input">
                    <input
                      id="m_phone2"
                      type="text"
                      name="m_phone2"
                      className="border-0"
                      style={{ outline: "none", width: "100%" }}
                      placeholder="앞 번호"
                      onBlur={handleBlur}
                    ></input>
                  </div>
                </Col>
                <Col sm={4} className="px-0" style={{ marginLeft: "40px" }}>
                  <div className="signup-input">
                    <input
                      id="m_phone3"
                      type="text"
                      name="m_phone3"
                      className="border-0"
                      style={{ outline: "none", width: "100%" }}
                      placeholder="뒤 4자리"
                      onBlur={handleBlur}
                    ></input>
                  </div>
                </Col>
              </Row>
              {errorName === "m_phone1" ? (
                <ErrorMessage errorMessage={errorMessage} />
              ) : null}
            </div>

            {/* 가입하기 버튼 */}
            <div className="mt-5">
              <Row>
                <div
                  className="signup-btn-wrap mx-auto d-flex justify-content-center"
                  style={{ width: "97%", background: "#5a83c5" }}
                  onClick={handleClick}
                >
                  가입하기
                </div>
              </Row>
            </div>
          </form>
        </Container>
      </div>
    </div>
  );
};

export default SignUp;
