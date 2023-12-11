import React from "react";
import { Col, Container, Row } from "react-bootstrap";
import MyNavbar from "../components/MyNavBar";
import WriteList from "./writeList";

export function FullWriteList() {
  return (
    <Container>
      <Row>
        <MyNavbar />

        <WriteList />
      </Row>
    </Container>
  );
}
