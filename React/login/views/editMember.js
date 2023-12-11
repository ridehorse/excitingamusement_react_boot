import React, { useEffect, useRef, useState } from "react";

import Container from "react-bootstrap/Container";
import Row from "react-bootstrap/Row";
import Col from "react-bootstrap/Col";
import { call, EditMemberCom } from "../service/ApiService";

import { useDaumPostcodePopup } from "react-daum-postcode";
import { EditProfile } from "../components/EditProfile";
import { SessionRemove } from "../service/sessionRemove";

const EditMember = () => {
  const [m_name, setM_name] = useState(null);
  const [m_email, setM_email] = useState(null);
  const [m_image, setM_image] = useState("");
  const [final, setFinal] = useState(null);

  const [pass, setPass] = useState(true);

  const member_id = sessionStorage.getItem("MEMBER_ID");
  const kakao_name = sessionStorage.getItem("KAKAO_NAME");
  const git_id = sessionStorage.getItem("GIT_ID");

  const request = {
    member_id: member_id,
  };

  const [o_phone, setO_phone] = useState("");
  const [o_address, setO_address] = useState("");
  const [o_birth, setO_birth] = useState("");
  const [o_email, setO_email] = useState("");
  const [o_gender, setO_gender] = useState("");
  useEffect(() => {
    if (kakao_name || git_id) {
      setPass(false);
    }

    call("/mypage/getMember", "POST", request)
      .then((response) => {
        console.log(response.m_email);
        console.log("getMember 입력 받음");
        setM_name(response.m_name);
        setM_email(response.m_email);
        setM_image(response.m_image);
        console.log("editMember / m_image : " + m_image);

        setO_phone(response.m_phone);
        setO_address(response.m_address);
        setO_birth(response.m_birth);
        setO_email(response.m_email);
        setO_gender(response.m_gender);
      })
      .catch((err) => {
        console.log(err);
      });
  }, []);

  useEffect(() => {
    if (final !== null) {
      const request = {
        member_id: formData.member_id,
        m_email: formData.m_email,
        m_birth: formData.m_birth,
        m_phone: formData.m_phone,
        m_address: formData.m_address,
      };

      console.log("밑에 hanldeClickHidden 들어간 후 formData");
      console.log(formData);
      console.log("formData.m_address : " + formData.m_address);
      console.log("formData.m_email : " + formData.m_email);
      console.log("formData.m_birth : " + formData.m_birth);
      console.log("formData.m_phone : " + formData.m_phone);

      call("/mypage/editMember", "POST", request).then((response) => {
        if (response === 1) {
          console.log("editmember 수정 성공");
          alert("정보수정이 성공적으로 완료되었습니다.");
          window.location.href = "/";
        } else {
          console.log("editmember 수정 실패");
        }
      });
    }
  }, [final]);

  const [formData, setFormData] = useState({
    member_id: member_id,
    m_pass: "",
    m_pass2: "",
    email1: "",
    email2: "",
    address1: "",
    address2: "",
    address3: "",
    year: "",
    month: "",
    day: "",
    m_address: "",
    m_email: "",
    m_birth: "",
    emailSelect: "",
    addressAuto: "",
  });

  function handleInputChange(e) {
    const { name, value } = e.target;

    console.log("name : " + name + " , value : " + value);
    setFormData((prevData) => ({
      ...prevData,
      [name]: value,
    }));
  }

  function hadleclickEmail(e) {
    formRef.current.querySelector("#email2").value = e.target.value;
    const { name, value } = e.target;
    setFormData((prevData) => ({
      ...prevData,
      [name]: value,
    }));
  }

  //회원탈퇴
  function handleClickBye() {
    const confirmation = window.confirm("회원탈퇴 하시겠습니까?");

    const request = {
      member_id: member_id,
    };
    if (confirmation) {
      call("/mypage/byebye", "POST", request)
        .then((data) => {
          if (data === 1) {
            alert("회원탈퇴가 정상적으로 진행되었습니다.");
            SessionRemove();
            window.location.href = "/";
          }
        })
        .catch((err) => {
          console.log(err);
        });
    } else {
      return;
    }
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

    console.log(fullAddress); // e.g. '서울 성동구 왕십리로2길 20 (성수동1가)'
    // console.log(formRef.current.querySelector("#address2").value);
    formRef.current.querySelector("#address1").value = data.zonecode;
    formRef.current.querySelector("#address2").value = fullAddress;

    setFormData((prevData) => ({
      ...prevData,
      addressAuto: data.zonecode + "/" + fullAddress,
    }));
  };

  function clickhandlejuso() {
    open({ onComplete: handleComplete });
  }

  const formRef = useRef(null);

  console.log("밑에 hanldeClickEdit 들어가기전에 formData");
  console.log(formData);
  function handleClickEdit() {
    if (!formData.addressAuto) {
      setFormData((prevData) => ({
        ...prevData,
        m_address: o_address,
      }));
    }

    if (!formData.year || !formData.month || !formData.day) {
      setFormData((prevData) => ({
        ...prevData,
        m_birth: o_birth,
      }));
    }

    if (!formData.email2 && !formData.emailSelect) {
      setFormData((prevData) => ({
        ...prevData,
        m_email: o_email,
      }));
    }

    if (!formData.email1) {
      setFormData((prevData) => ({
        ...prevData,
        m_email: o_email,
      }));
    }

    if (!formData.phone1 || !formData.phone2 || !formData.phone3) {
      setFormData((prevData) => ({
        ...prevData,
        m_phone: o_phone,
      }));
    }

    if (formData.addressAuto) {
      setFormData((prevData) => ({
        ...prevData,
        m_address: formData.addressAuto + " " + formData.address3,
      }));
    }

    if (formData.year && formData.month && formData.day) {
      setFormData((prevData) => ({
        ...prevData,
        m_birth: formData.year + formData.month + formData.day,
      }));
    }

    if (formData.email1 && formData.email2) {
      setFormData((prevData) => ({
        ...prevData,
        m_email: formData.email1 + "@" + formData.email2,
      }));
    }

    if (formData.email1 && formData.emailSelect) {
      setFormData((prevData) => ({
        ...prevData,
        m_email: formData.email1 + "@" + formData.emailSelect,
      }));
    }

    if (formData.phone1 && formData.phone2 && formData.phone3) {
      setFormData((prevData) => ({
        ...prevData,
        m_phone: formData.phone1 + formData.phone2 + formData.phone3,
      }));
    }

    // let m_pass = "";
    // if (formRef.current.querySelector("#m_pass").value) {
    //   m_pass = formRef.current.querySelector("#m_pass").value;
    //   console.log(m_pass);
    // } else {
    //   m_pass = o_pass;
    // }

    // let phone1 = "";
    // if (formRef.current.querySelector("#phone1").value) {
    //   phone1 = formRef.current.querySelector("#phone1").value;
    // }

    // let phone2 = "";
    // if (formRef.current.querySelector("#phone2").value) {
    //   phone2 = formRef.current.querySelector("#phone2").value;
    // }

    // let phone3 = "";
    // if (formRef.current.querySelector("#phone3").value) {
    //   phone3 = formRef.current.querySelector("#phone3").value;
    // }

    // let email1 = "";
    // if (formRef.current.querySelector("#email1").value) {
    //   email1 = formRef.current.querySelector("#email1").value;
    // }

    // let email2 = "";
    // if (formRef.current.querySelector("#email2").value) {
    //   email2 = formRef.current.querySelector("#email2").value;
    // }

    // let address1 = "";
    // if (formRef.current.querySelector("#m_address1").value) {
    //   address1 = formRef.current.querySelector("#m_address1").value;
    // }

    // let address2 = "";
    // if (formRef.current.querySelector("#m_address2").value) {
    //   address2 = formRef.current.querySelector("#m_address2").value;
    // }

    // let address3 = "";
    // if (formRef.current.querySelector("#m_address3").value) {
    //   address3 = formRef.current.querySelector("#m_address3").value;
    // }

    // let year = "";
    // if (formRef.current.querySelector("#year").value) {
    //   year = formRef.current.querySelector("#year").value;
    // }

    // let month = "";
    // if (formRef.current.querySelector("#month").value) {
    //   month = formRef.current.querySelector("#month").value;
    // }

    // let day = "";
    // if (formRef.current.querySelector("#day").value) {
    //   day = formRef.current.querySelector("#day").value;
    // }

    // console.log(
    //   m_pass,
    //   phone1,
    //   phone2,
    //   phone3,
    //   email1,
    //   email2,
    //   address1,
    //   address2,
    //   address3,
    //   year,
    //   month,
    //   day
    // );

    // let m_phone = phone1 + phone2 + phone3;
    // let m_email = email1 + "@" + email2;
    // let m_birth = year + month + day;
    // let m_address = address1 + "/" + address2 + " " + address3;

    // const request = {
    //   member_id: member_id,
    //   m_email: formData.m_email,
    //   m_birth: formData.m_birth,
    //   m_phone: formData.m_phone,
    //   m_address: formData.m_address,
    // };

    // formRef.current.querySelector("#hidden").click();
    setFinal(true);
  }

  // function handleClickHidden() {
  //   console.log("밑에 hanldeClickHidden 들어간 후 formData");
  //   console.log(formData);
  //   console.log("formData.m_address : " + formData.m_address);
  //   console.log("formData.m_email : " + formData.m_email);
  //   console.log("formData.m_birth : " + formData.m_birth);
  //   console.log("formData.m_phone : " + formData.m_phone);

  //   call("/mypage/editMember", "POST", request).then((response) => {
  //     if (response === 1) {
  //       console.log("editmember 수정 성공");
  //       alert("정보수정이 성공적으로 완료되었습니다.");
  //       // window.location.href = "/main";
  //     } else {
  //       console.log("editmember 수정 실패");
  //     }
  //   });
  // }

  const buttonStyle = {
    width: "80px",
    height: "25px",
    background: "#5a83c5",
    color: "#fff",
    fontSize: "14px",
    border: "1px solid black",
    borderRadius: "1px",
    cursor: "pointer",
  };
  const buttonStyle2 = {
    width: "220px",
    height: "40px",
    background: "#5a83c5",
    color: "#fff",
    fontSize: "14px",
    border: "none",
    borderRadius: "1px",
    cursor: "pointer",
  };

  return (
    <Col xs={9}>
      <div className="d-flex justify-content-center">
        <div style={{ width: "540px" }}>
          <Container>
            <Row style={{ marginTop: "40px" }}>
              <Col style={{ borderLeft: "4px solid #5a83c5" }}>
                <span style={{ fontSize: "20px", fontWeight: "bold" }}>
                  회원정보{" "}
                </span>
                <span
                  style={{
                    fontSize: "20px",
                    color: "green",
                    fontWeight: "bold",
                  }}
                >
                  수정
                </span>
              </Col>
            </Row>
          </Container>

          {/* 사진전송 + 상단 프로필 */}
          <EditProfile />

          <Container>
            <form ref={formRef}>
              <input
                type="hidden"
                name="hidden"
                id="hidden"
                // onClick={handleClickHidden}
              />
              <Row style={{ marginTop: "40px" }}>
                <div
                  className="ps-2 border-bottom border-2 border-success pb-1"
                  style={{ fontSize: "18px", fontWeight: "bold" }}
                >
                  필수 회원 정보
                </div>
              </Row>

              {/* {pass ? (
                <Row style={{ marginTop: "25px" }}>
                  <Col sm={3} style={{ fontSize: "14px" }}>
                    비밀번호
                  </Col>
                  <Col sm={1} className="border-start border-1">
                    {" "}
                  </Col>
                  <Col>
                    <input
                      onChange={handleInputChange}
                      type="text"
                      id="m_pass"
                      name="m_pass"
                      style={{ height: "23px", fontSize: "14px" }}
                    />
                  </Col>
                </Row>
              ) : (
                ""
              )}
              {pass ? (
                <Row style={{ marginTop: "11px" }}>
                  <Col sm={3} style={{ fontSize: "14px" }}>
                    비밀번호 확인
                  </Col>
                  <Col sm={1} className="border-start border-1">
                    {" "}
                  </Col>
                  <Col>
                    <input
                      onChange={handleInputChange}
                      type="text"
                      id="m_pass2"
                      name="m_pass2"
                      style={{ height: "23px", fontSize: "14px" }}
                    />
                  </Col>
                </Row>
              ) : (
                ""
              )} */}
              <Row style={{ marginTop: "11px" }}>
                <Col sm={3} style={{ fontSize: "14px" }}>
                  휴대전화
                </Col>
                <Col sm={1} className="border-start border-1">
                  {" "}
                </Col>
                <Col sm={2} style={{ width: "70px" }}>
                  <input
                    onChange={handleInputChange}
                    type="text"
                    id="phone1"
                    name="phone1"
                    style={{ height: "23px", width: "60px", fontSize: "14px" }}
                  />
                </Col>
                <Col sm={3} style={{ width: "110px" }}>
                  <input
                    onChange={handleInputChange}
                    type="text"
                    id="phone2"
                    name="phone2"
                    style={{ height: "23px", width: "100px", fontSize: "14px" }}
                  />
                </Col>
                <Col sm={3}>
                  <input
                    onChange={handleInputChange}
                    type="text"
                    id="phone3"
                    name="phone3"
                    style={{ height: "23px", width: "100px", fontSize: "14px" }}
                  />
                </Col>
              </Row>
              <Row style={{ marginTop: "11px" }}>
                <Col sm={3} style={{ fontSize: "14px" }}>
                  이메일
                </Col>
                <Col sm={1} className="border-start border-1">
                  {" "}
                </Col>
                <Col sm={3} style={{ width: "110px" }}>
                  <input
                    onChange={handleInputChange}
                    type="text"
                    id="email1"
                    name="email1"
                    style={{ height: "23px", width: "100px", fontSize: "14px" }}
                  />
                </Col>
                <Col sm={1} style={{ width: "27px" }}>
                  @
                </Col>
                <Col sm={3} style={{ width: "110px" }}>
                  <input
                    onChange={handleInputChange}
                    type="text"
                    id="email2"
                    name="email2"
                    style={{ height: "23px", width: "100px", fontSize: "14px" }}
                  />
                </Col>
                <Col sm={3} style={{ width: "110px" }}>
                  <select
                    id="emailSelect"
                    className="selectbox"
                    name="emailSelect"
                    style={{ width: "100%" }}
                    onClick={hadleclickEmail}
                  >
                    <option value="">---------</option>
                    <option value="gmail.com">gmail.com</option>
                    <option value="naver.com">naver.com</option>
                    <option value="daum.net">daum.net</option>
                  </select>
                </Col>
              </Row>
              <Row style={{ marginTop: "11px" }}>
                <Col sm={3} style={{ fontSize: "14px" }}>
                  주소
                </Col>
                <Col sm={1} className="border-start border-1">
                  {" "}
                </Col>
                <Col>
                  <input
                    onChange={handleInputChange}
                    type="text"
                    id="address1"
                    name="address1"
                    style={{ height: "23px", width: "100px", fontSize: "14px" }}
                    readOnly
                  />
                </Col>
                <Col style={{ width: "90px" }}>
                  <input
                    type="button"
                    id="juso"
                    name="juso"
                    style={buttonStyle}
                    value="주소찾기"
                    onClick={clickhandlejuso}
                  />
                </Col>
              </Row>
              <Row style={{ marginLeft: "168px", marginTop: "4px" }}>
                <Col style={{ width: "240px" }}>
                  <input
                    onChange={handleInputChange}
                    type="text"
                    id="address2"
                    name="address2"
                    style={{ height: "23px", width: "260px", fontSize: "14px" }}
                    readOnly
                  />
                </Col>
              </Row>
              <Row style={{ marginLeft: "168px", marginTop: "4px" }}>
                <Col style={{ width: "240px" }}>
                  <input
                    onChange={handleInputChange}
                    type="text"
                    id="address3"
                    name="address3"
                    style={{ height: "23px", width: "260px", fontSize: "14px" }}
                  />
                </Col>
              </Row>
              <Row style={{ marginTop: "40px" }}>
                <div
                  className="ps-2 border-bottom border-2 pb-1"
                  style={{ fontSize: "18px", fontWeight: "bold" }}
                >
                  추가 회원 정보
                </div>
              </Row>

              <Row style={{ marginTop: "11px" }}>
                <Col sm={3} style={{ fontSize: "14px" }}>
                  생년월일
                </Col>
                <Col sm={1} className="border-start border-1">
                  {" "}
                </Col>
                <Col sm={3} style={{ width: "80px" }}>
                  <input
                    onChange={handleInputChange}
                    type="text"
                    id="year"
                    name="year"
                    style={{ height: "23px", width: "70px", fontSize: "14px" }}
                  />
                </Col>
                <Col sm={1} style={{ width: "27px", fontSize: "14px" }}>
                  년
                </Col>
                <Col sm={3} style={{ width: "80px" }}>
                  <select
                    onChange={handleInputChange}
                    id="month"
                    className="selectbox"
                    name="month"
                    style={{ width: "70px" }}
                  >
                    <option value="">------</option>
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
                </Col>
                <Col sm={1} style={{ width: "27px", fontSize: "14px" }}>
                  월
                </Col>
                <Col sm={3} style={{ width: "80px" }}>
                  <input
                    onChange={handleInputChange}
                    type="text"
                    id="day"
                    name="day"
                    style={{ height: "23px", width: "70px", fontSize: "14px" }}
                  />
                </Col>
                <Col sm={1} style={{ width: "27px", fontSize: "14px" }}>
                  일
                </Col>
              </Row>
              <Row
                className="d-flex justify-content-center"
                style={{ marginTop: "60px" }}
              >
                <input
                  type="button"
                  value="수정하기"
                  onClick={handleClickEdit}
                  style={buttonStyle2}
                />
              </Row>
              <Row style={{ marginTop: "90px" }}>
                <div
                  className="ps-2 border-bottom border-2 pt-1"
                  style={{ fontSize: "18px", fontWeight: "bold" }}
                ></div>
              </Row>
              <Row style={{ marginTop: "11px" }}>
                <Col sm={3} style={{ fontSize: "14px" }}>
                  회원 탈퇴
                </Col>
                <Col sm={1} className="border-start border-1">
                  {" "}
                </Col>
                <Col style={{ fontSize: "13px" }}>
                  <input
                    type="button"
                    value="회원탈퇴"
                    style={{ width: "80px" }}
                    onClick={handleClickBye}
                  />
                </Col>
              </Row>
              <Row style={{ marginBottom: "60px" }}>
                <Col sm={1}></Col>
                <Col
                  className="text-muted"
                  style={{ fontSize: "11px", marginTop: "14px" }}
                >
                  *탈퇴 신청 즉시{" "}
                  <span style={{ color: "red" }}>
                    자유이용권,프로모션 등 유료 서비스
                  </span>
                  에 대한 정보와 작성 된 게시물이 삭제됩니다.
                </Col>
              </Row>
            </form>
          </Container>
        </div>
      </div>
    </Col>
  );
};

export default EditMember;
