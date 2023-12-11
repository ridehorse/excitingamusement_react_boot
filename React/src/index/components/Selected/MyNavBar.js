import React from 'react';
import {
  Accordion,
  Button,
  Col,
  Collapse,
  Container,
  Nav,
  Row,
} from 'react-bootstrap';
import { Link } from 'react-router-dom';

const MyNavbar = () => {
  sessionStorage.setItem('member_id','hong1');
  const member_id = sessionStorage.getItem('member_id'); 

  return (
    <Col xs={3} className='my-5'>
      <Row className="rounded shadow mb-5" style={{ height: '100px' }}>
        <div id="divimage">
          <i
            className="bi bi-person-circle"
            id="iimage"
            style={{ fontSize: '2.5rem', color: 'cornflowerblue' }}
          >
            &nbsp;
          </i>
          {member_id}님 환영합니다
        </div>
      </Row>
      <Row>
        <Accordion flush>
          <Accordion.Item eventKey="0">
            <Accordion.Header>
              <i className="bi bi-clipboard-check"></i>나의 활동 정보
            </Accordion.Header>
            <Accordion.Body>
              <Link to="/orderlist" className="text-decoration-none text-dark">
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
              <Link to="/writeList" className="text-decoration-none text-dark">
                <div className="rounded shadow mb-3 p-3">
                  <i className="bi bi-chat-right-text"></i>댓글 리스트
                </div>
              </Link>
              <Link
                to="/refund"
                className="text-decoration-none text-danger"
              >
                <div className="rounded shadow mb-3 p-3">
                  <i className="bi bi-cart-dash-fill text-danger"></i>환불 신청
                </div>
              </Link>
            </Accordion.Body>
          </Accordion.Item>
        </Accordion>
        <Nav className="flex-column mb-5">
          <Link to="/editMember" className="text-decoration-none text-dark">
            <div className="rounded shadow mb-3 p-3">
              <i className="bi bi-person-gear"></i>내 정보 수정
            </div>
          </Link>
          <Link
            to="/mypoint"
            className="text-decoration-none text-dark"
          >
            <div className="rounded shadow mb-3 p-3">
              <i className="bi bi-credit-card"></i>나의 포인트
            </div>
          </Link>
        </Nav>
      </Row>
      <Row className="rounded shadow mb-5" style={{ height: '130px' }}>
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
      <Link to="/logout" className="d-block text-decoration-none text-dark">
        <div className="row rounded shadow p-3">로그아웃</div>
      </Link>
    </Col>
  );
};

export default MyNavbar;
