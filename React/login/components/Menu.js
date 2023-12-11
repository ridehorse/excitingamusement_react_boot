import { useEffect, useState } from "react";
import Button from "react-bootstrap/Button";
import Container from "react-bootstrap/Container";
import Form from "react-bootstrap/Form";
import Nav from "react-bootstrap/Nav";
import Navbar from "react-bootstrap/Navbar";
import Offcanvas from "react-bootstrap/Offcanvas";
import { Link, Route } from "react-router-dom";
import { call } from "../service/ApiService";
import { HeaderLogin, HeaderLogout, Profile } from "./headerComponents";

function Menu({ onChangeSearchName, searchNameRef }) {
  const [member_id, setMember_id] = useState("");
  const [kakao_id, setKakao_id] = useState("");
  const [m_image, setM_image] = useState("");
  const [kakao_name, setKakao_name] = useState("");
  const [git_id, setGit_id] = useState("");
  const [naver_id, setNaver_id] = useState("");

  // 카카오로그인
  useEffect(() => {
    if (
      sessionStorage.getItem("MEMBER_ID") &&
      sessionStorage.getItem("KAKAO_ID")
    ) {
      console.log("카카오로그인 접속");
      setKakao_name(sessionStorage.getItem("KAKAO_NAME"));
      setMember_id(sessionStorage.getItem("MEMBER_ID"));
      setKakao_id(sessionStorage.getItem("KAKAO_ID"));

      // git로그인
    } else if (
      sessionStorage.getItem("MEMBER_ID") &&
      sessionStorage.getItem("GIT_ID")
    ) {
      console.log("git로그인 접속");

      setGit_id(sessionStorage.getItem("GIT_ID"));    
      
      // naver로그인
    } else if (
      sessionStorage.getItem("MEMBER_ID") &&
      sessionStorage.getItem("NAVER_ID")
    ) {
      console.log("naver로그인 접속");

      setNaver_id(sessionStorage.getItem("NAVER_ID"));

      // 일반로그인
    } else if (sessionStorage.getItem("MEMBER_ID")) {
      console.log("일반로그인 접속");
      
      // 비로그인
    } else {
    }
    
    // 헤더바에 image 표출하기 위한 통신(member_Id에 저장된 정보 가지고 온다)
    if(sessionStorage.getItem("MEMBER_ID")){
      const request = {
        member_id: sessionStorage.getItem("MEMBER_ID"),
      };
      call("/mypage/getMember", "POST", request).then((response) => {
        console.log(response.member_id);
        console.log("Menu // getMember 입력 받음");
        console.log("Menu // getMember // m_image : " + response.m_image);
        setMember_id(response.member_id);
        setM_image(response.m_image);
      });
   }

  }, []);
  if (window.location.pathname === "/kakaoInter") {
    return null;
  }
  if (window.location.pathname === "/kakaoLogin") {
    return null;
  }

  return (
    <header className=" header">
      {["sm"].map((expand) => (
        <Navbar key={expand} expand={expand} className="bg-body-tertiary mb-3">
          <Container fluid>
            <Navbar.Brand href="/">
              <img
                src="https://play-lh.googleusercontent.com/W9AN3AyNH7rgBaGO7Jv2MEMk2piGUEerZTZN7hG-xNJFq6QW1Dzs4HLukka0-oKIsw"
                width="40px"
                alt="img"
              />
            </Navbar.Brand>
            <Navbar.Toggle aria-controls={`offcanvasNavbar-expand-${expand}`} />

            <Navbar.Offcanvas
              id={`offcanvasNavbar-expand-${expand}`}
              aria-labelledby={`offcanvasNavbarLabel-expand-${expand}`}
              placement="end"
            >
              <Offcanvas.Header closeButton>
                <Offcanvas.Title id={`offcanvasNavbarLabel-expand-${expand}`}>
                  Offcanvas
                </Offcanvas.Title>
              </Offcanvas.Header>
              <Offcanvas.Body>
                <Nav className="justify-content-end flex-grow-1 pe-3">
                  {/* <Nav.Link href="/test" style={{ fontSize: "15px" }}>
                    테스트
                  </Nav.Link> */}
                  <Nav.Link
                    href="/announcement"
                    style={{ fontSize: "14px", paddingTop: "13px" }}
                  >
                    고객센터
                  </Nav.Link>
                  <Nav.Link
                    href="/promotion"
                    style={{ fontSize: "14px", paddingTop: "13px" }}
                  >
                    프로모션
                  </Nav.Link>
                  <Nav.Link
                    href="/board"
                    style={{ fontSize: "14px", paddingTop: "13px" }}
                  >
                    게시판
                  </Nav.Link>
                  <Nav.Link
                    href="/list"
                    className="link-danger"
                    style={{ fontSize: "14px", paddingTop: "13px" }}
                  >
                    놀이공원
                  </Nav.Link>
                  {/* 로그인 링크 */}
                  <HeaderLogin />
                  {/* 로그아웃 링크 */}
                  <HeaderLogout
                    setM_image={setM_image}
                    setMember_id={setMember_id}
                    setKakao_id={setKakao_id}
                  />
                  {/* 프로필 */}
                  <Profile
                    member_id={member_id}
                    kakao_id={kakao_id}
                    m_image={m_image}
                    kakao_name={kakao_name}
                    git_id={git_id}
                    naver_id={naver_id}
                  />
                  <Form
                    action="/list"
                    className="d-flex"
                    style={{ padding: "5px" }}
                  >
                    <Form.Control
                      type="search"
                      placeholder="Search"
                      className="me-2"
                      aria-label="Search"
                      name="searchName"
                      onChange={onChangeSearchName}
                      style={{
                        width: "120px",
                        fontSize: "14px",
                        borderRadius: "0px",
                      }}
                    />
                    <Button
                      type="button"
                      variant="outline-success"
                      style={{ borderRadius: "0px" }}
                    >
                      <Link
                        to={{
                          pathname: "/list",
                          state: {
                            searchNameRef: "1",
                          },
                        }}
                        style={{
                          color: "inherit",
                          textDecoration: "none",
                        }}
                      >
                        search
                      </Link>
                    </Button>
                  </Form>
                </Nav>
              </Offcanvas.Body>
            </Navbar.Offcanvas>
          </Container>
        </Navbar>
      ))}
    </header>
  );
}

export default Menu;
