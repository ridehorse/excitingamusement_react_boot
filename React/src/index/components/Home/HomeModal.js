import React, { useRef, useState } from 'react';
import { Button, Modal } from 'react-bootstrap';
import { useCookies } from 'react-cookie';

const HomeModal = () => {
  const [show, setShow] = useState(true);
  const checkboxRef = useRef(null);
  const [cookies, setCookie] = useCookies(['modalClosed']);

  const handleClose = () => {
    if (checkboxRef.current.checked) {
      setCookie('modalClosed', { maxAge: 86400 });
      setShow(false);
    }
    setShow(false);
  };

  // 쿠키 값이 true인 경우 모달을 닫습니다.
  if (cookies.modalClosed) {
    return null;
  }

  return (
    <Modal show={show} onHide={handleClose} centered style={{zIndex:'99999'}}>
      <Modal.Header closeButton>
        <Modal.Title>이벤트 공지사항</Modal.Title>
      </Modal.Header>
      <Modal.Body className="text-center" style={{height:'auto'}}>
        <a href="/promotion">
          <img
            className="img-responsive"
            src="https://openimage.interpark.com/tourpark/tour/event/2017/170614_china/181106_china_01.jpg"
            style={{ width: '450px' }}
            alt="Event"
          />
        </a>
      </Modal.Body>
      <Modal.Footer>
        <form name="popFrm">
          <input
            type="checkbox"
            className="btn"
            id="inactiveToday"
            value="1"
            ref={checkboxRef}
          />
          <label htmlFor="inactiveToday">하루 동안 열지 않음</label>
          <Button variant="dark" onClick={handleClose}>
            닫기
          </Button>
        </form>
      </Modal.Footer>
    </Modal>
  );
};

export default HomeModal;
