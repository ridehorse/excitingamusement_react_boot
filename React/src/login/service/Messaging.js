import React, { useRef, useState } from "react";

import Row from "react-bootstrap/Row";

export function CorrectMessage({ correctMessage }) {
  return (
    <Row>
      {correctMessage && (
        <div
          className="correct-message mt-1"
          style={{ fontSize: "15px", color: "blue" }}
        >
          {correctMessage}
        </div>
      )}
    </Row>
  );
}

export function ErrorMessage({ errorMessage }) {
  return (
    <Row>
      {errorMessage && (
        <div
          className="error-message mt-1"
          style={{ fontSize: "15px", color: "lightcoral" }}
        >
          {errorMessage}
        </div>
      )}
    </Row>
  );
}
