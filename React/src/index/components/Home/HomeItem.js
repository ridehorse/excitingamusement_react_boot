// HomeItem.js
import React, { useState, useEffect } from 'react';
import { Card, Col } from 'react-bootstrap';
import axios from 'axios';
import { BsHeart, BsHeartFill } from 'react-icons/bs';
import 'animate.css';

const HomeItem = ({ item, member_id, handleShowToast }) => {
  const [isFavorite, setIsFavorite] = useState(false);
  const [animateHeart, setAnimateHeart] = useState(false);

  useEffect(() => {
      if (!member_id) return;
      axios.post('http://localhost:8080/selectedapi/check', {
        amuse_id: item.amuse_id,
        member_id
      })
      .then(response => {
        setIsFavorite(response.data.check === 1);
        console.log(response.data.check);
      })
      .catch(error => {
        console.error(error);
      });
  }, [item.amuse_id, member_id]);

  const handleHeartClick = () => {
    if (!member_id) {
      window.location.href = '/login';
      return;
    }
    
    if(animateHeart) return;
    setAnimateHeart(true);

    axios.post('http://localhost:8080/selectedapi/insertDelete', {
      amuse_id: item.amuse_id,
      member_id
    })
    .then(response => {
      setTimeout(() => {
        setIsFavorite(response.data.check === 1);
        setAnimateHeart(false);
        console.log(response.data.check);
        // 토스트 알림 처리
        if (response.data.check === 1) {
          handleShowToast('위시리스트에 추가되었어요', 'success');
        } else {
          handleShowToast('위시리스트에서 제외되었어요', 'failed');
        }
      },1000);

    })
    .catch(error => {
      console.error(error);
    });
  };

  return (
    <Col xs={12} md={6} lg={4} xl={3} key={item.amuse_id}>
      <Card className="shadow-sm overflow-hidden position-relative">
      <div className={`animate__animated position-absolute ${animateHeart ? 'animate__bounce' : ''}`} onClick={handleHeartClick} style={{width: '35px', top: '10px', right: '10px', zIndex: '100'}}>
        {isFavorite ? <BsHeartFill className="custom-icon" style={{fontSize: '2rem', color: 'red'}} /> : <BsHeart className="custom-icon" style={{fontSize: '2rem', color: 'red'}}/>}
      </div>
        <a
          href={`/amusement/${item.amuse_id}`}
          className="text-decoration-none text-dark"
        >
          <div className='overflow-hidden'>
          <Card.Img
            variant="top"
            src={item.url}
            alt="..."
            className="custom-card-img custom-focus overflow-hidden"
          />
          </div>
        </a>
        <Card.Body className="custom-card-body-height overflow-hidden">
          <Card.Title>{item.a_name}</Card.Title>
          <Card.Text>{item.a_country}</Card.Text>
        </Card.Body>
      </Card>
    </Col>
  );
};

export default HomeItem;
