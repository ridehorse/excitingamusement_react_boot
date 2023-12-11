import React from "react";
import { Container, Row, Col, ListGroup, ListGroupItem } from "react-bootstrap";

const Footer = () => {
  return (
    <footer className="my-5" style={{backgroundColor:'whitesmoke'}}>
    <Container fluid>
      <Row>
        <Col xs={12} md={3}>
          <ListGroup variant="flush">
            <ListGroupItem>고객지원실 운영안내</ListGroupItem>
            <ListGroupItem>월~금 09:30~06:30(점심시간 13:15~14:30)</ListGroupItem>
            <ListGroupItem>주말/공휴일 제외, 한국시간 기준</ListGroupItem>
          </ListGroup>
        </Col>
        <Col xs={{ span: 12, order: "first" }} md={{ span: 2, order: "last", offset: 3 }}>
          {/* order 속성을 사용해 모바일 환경에서 원하는 순서로 나타나도록 설정 */}
          <p>소개</p>
        </Col>
        <Col xs={12} md={2}>
          <p>파트너</p>
        </Col>
        <Col xs={12} md={2}>
          <p>지원</p>
        </Col>
      </Row>
    </Container>
  </footer>
  );
}

export default Footer