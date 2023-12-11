import React from "react";
import { Col, Container, Row } from "react-bootstrap";
import MyNavbar from "../components/MyNavBar";
import EditMember from "./editMember";

export function FullEditMember() {
  return (
    <Container>
      <Row>
        <MyNavbar />

        <EditMember />
      </Row>
    </Container>
  );
}
