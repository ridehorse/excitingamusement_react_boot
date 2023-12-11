import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { Card, Carousel, Col, Container, Row } from 'react-bootstrap';
import '../css/Home.css';
import HomeItem from '../components/Home/HomeItem';
import ToastNotification from '../components/ToastNotification';
import HomeModal from '../components/Home/HomeModal';

const Home = () => {
  const [data, setData] = useState(null);
  const member_id = sessionStorage.getItem('MEMBER_ID'); 
  const [toast, setToast] = useState({ show: false, message: "", type : "" });
  useEffect(() => {
    axios.get('http://localhost:8080/')
      .then((response) => {
        setData(response.data);
        console.log(response.data)
      })
      .catch((error) => {
        console.log(error);
      });
  }, []);

  const handleShowToast = (message, type) => {
    setToast({ show: true, message, type });
    setTimeout(() => {
      setToast({ show: false, message: '', type });
    }, 1200);
  };

  return (
    <div>
        
    <main className="container custom-main-padding border-bottom">
      <Container>
        <Row>
          <Carousel id="carouselExampleInterval">
            {data && data.promotionData.map((fData) => (
              <Carousel.Item key={fData.promotion_img}>
                <img
                  className="d-block w-100 custom-carousel-img"
                  src={fData.promotion_img}
                  style={{height:'600px'}}
                  alt="..."
                />
                <Carousel.Caption className="d-none d-md-block"
                  style={{fontSize:'2.5rem', fontWeight:'bold'}}>
                  <h2>{fData.promotion_content}</h2>
                  <p>{fData.promotion_name}</p>
                </Carousel.Caption>
              </Carousel.Item>
            ))}
          </Carousel>
        </Row>

        <hr />
        <Row className="pt-5 pb-2">
          <h4>
            <a className="text-decoration-none text-dark" href="/list">
              국내 놀이공원
            </a>
          </h4>
        </Row>

        <div className="album py-5 bg-light">
          <Container>
            <Row className="g-5">
              {data && data.koreaData.map((kData) => (
                <HomeItem key={kData.amuse_id} item={kData} member_id={member_id} handleShowToast={handleShowToast}/>
              ))}
            </Row>
          </Container>
        </div>

        <hr />
        <Row className="pt-5 pb-2">
          <h4>
            <a className="text-decoration-none text-dark" href="/list">
              해외 놀이공원
            </a>
          </h4>
        </Row>

        <div className="album py-5 bg-light">
          <Container>
            <Row className="g-5">
              {data && data.foreignData.map((fData) => (
                <HomeItem key={fData.amuse_id} item={fData} member_id={member_id} handleShowToast={handleShowToast} />
              ))}
            </Row>
          </Container>
        </div>
      </Container>
    </main>
    <HomeModal />
    <ToastNotification toast={toast} />         
    </div>
  );
}

export default Home;