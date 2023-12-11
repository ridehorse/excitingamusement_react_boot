import React from "react";
import {
  Accordion,
  Button,
  Col,
  Collapse,
  Container,
  Nav,
  Row,
} from "react-bootstrap";
import { Link } from "react-router-dom";
import { SessionRemove } from "../service/sessionRemove";

const MyNavbar = () => {
  const member_id = sessionStorage.getItem("MEMBER_ID"); // 세션에서 가져올 사용자 이름. 실제로는 서버에서 가져온 데이터로 구현해야 함
  const kakao_name = sessionStorage.getItem("KAKAO_NAME");
  const git_id = sessionStorage.getItem("GIT_ID");

  function handleClickLogout() {
    const confirmLogout = window.confirm("로그아웃 하시겠습니까?");
    if (confirmLogout) {
      SessionRemove();
      window.location.href = "/login";
    } else {
      return;
    }
  }

  return (
    <Col xs={3} className="my-5">
      <Row className="rounded-0 shadow mb-5" style={{ height: "100px" }}>
        <div
          id="divimage"
          className="text-center"
          style={{ marginTop: "20px" }}
        >
          {/* <i
            className="bi bi-person-circle"
            id="iimage"
            style={{ fontSize: "2.5rem", color: "cornflowerblue" }}
          >
            &nbsp;
          </i> */}
          <span style={{ fontWeight: "bold" }}>
            {kakao_name || git_id || member_id}
          </span>
          님 환영합니다
        </div>
      </Row>
      <Row>
        <Accordion flush>
          <Accordion.Item eventKey="0">
            <Accordion.Header style={{ marginBottom: "25px" }}>
              <i className="bi bi-clipboard-check rounded-0"></i>나의 활동 정보
            </Accordion.Header>
            <Accordion.Body>
              <Link
                to="/orderlist"
                className="text-decoration-none text-dark"
              >
                <div className="rounded shadow mb-3 p-3">
                  <i className="bi bi-cart"></i>구매 내역
                </div>
              </Link>
              <Link
                to="/mypage/selectedmypage"
                className="text-decoration-none text-dark"
              >
                <div className="rounded shadow mb-3 p-3">
                  <i className="bi bi-bookmark-heart"></i>위시리스트
                </div>
              </Link>
              <Link
                to="/writeList/1"
                className="text-decoration-none text-dark"
              >
                <div className="rounded shadow mb-3 p-3">
                  <i className="bi bi-chat-right-text"></i>댓글 리스트
                </div>
              </Link>
              <Link
                to="/mypage/refund"
                className="text-decoration-none text-danger"
              >
                <div className="rounded shadow mb-3 p-3">
                  <i className="bi bi-cart-dash-fill text-danger"></i>환불 신청
                </div>
              </Link>
            </Accordion.Body>
          </Accordion.Item>
        </Accordion>
        <Nav className="flex-column mb-5 ms-2">
          <Link to="/editMember" className="text-decoration-none text-dark">
            <div className="rounded-0 shadow mb-3 p-3">
              <i className="bi bi-person-gear "></i>내 정보 수정
            </div>
          </Link>
          <Link to="/mypoint" className="text-decoration-none text-dark">
            <div className="rounded-0 shadow mb-3 p-3">
              <i className="bi bi-credit-card"></i>나의 포인트
            </div>
          </Link>
        </Nav>
      </Row>
      <Row className="rounded shadow mb-5" style={{ height: "130px" }}>
        <Link
          to="/customer/faq?f_type="
          className="d-block text-decoration-none"
        >
          <div className="rounded shadow my-3 p-2 bg-dark text-white">
            <i className="bi bi-question-circle"></i>FAQ
          </div>
        </Link>
        <Link
          to="/customer/announcementInquiry"
          className="d-block text-decoration-none"
        >
          <div className="rounded shadow mb-2 p-2 bg-dark text-white">
            <i className="bi bi-chat-dots"></i>체험단 문의하기
          </div>
        </Link>
      </Row>
      <Link className="d-block text-decoration-none text-dark">
        <div className="row rounded shadow p-3" onClick={handleClickLogout}>
          로그아웃
        </div>
      </Link>
    </Col>
  );
};

export default MyNavbar;
