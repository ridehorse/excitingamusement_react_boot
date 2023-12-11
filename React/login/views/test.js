import React from "react";
import { NavDropdown } from "react-bootstrap";
import { PersonCircle } from "react-bootstrap-icons";

export function Test() {
  console.log("test :" + document.referrer);
  const pathName = new URL(document.referrer).pathname;
  console.log("pahtName : " + pathName);

  const m_image = "";
  const kakao_image =
    "http://k.kakaocdn.net/dn/bT1BxA/btscQPF2Kza/WUocO8hyTOwJISJkFnelxK/img_640x640.jpg";
  return (
    <NavDropdown
      title={
        <div>
          {m_image ? (
            <img
              src={require("../img/profileImg/" + m_image)}
              style={{ width: "30px", height: "30px" }}
              className="border rounded-circle"
              alt="img"
            />
          ) : kakao_image ? (
            <img
              src={kakao_image}
              style={{ width: "30px", height: "30px" }}
              className="border rounded-circle"
              alt="img"
            />
          ) : (
            <div style={{ width: "30px", height: "30px" }}>
              <PersonCircle style={{ width: "30px", height: "30px" }} />
            </div>
          )}
          <span>hong1</span>
        </div>
      }
      id="nav-dropdown"
    >
      <NavDropdown.Item eventKey="4.1">정보수정</NavDropdown.Item>
      <NavDropdown.Item eventKey="4.2">Another action</NavDropdown.Item>
      <NavDropdown.Item eventKey="4.3">Something else here</NavDropdown.Item>
      <NavDropdown.Divider />
      <NavDropdown.Item eventKey="4.4">Separated link</NavDropdown.Item>
    </NavDropdown>
  );
}
