import React from 'react'
import { Container, Row } from 'react-bootstrap'
import MyNavbar from "../../login/components/MyNavBar";
import SelectedBody from '../components/Selected/SelectedBody'

const SelectedMyPage = () => {
  return (
    <Container>
      <Row>
        <MyNavbar />
        <SelectedBody />
      </Row>
    </Container>
  )
}

export default SelectedMyPage