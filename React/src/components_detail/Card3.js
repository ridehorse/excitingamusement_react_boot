import { useNavigate } from "react-router-dom";

import "./card3.scss";

import { Button, Card, CardBody, CardFooter, Col } from 'reactstrap';
import 'bootstrap/dist/css/bootstrap.min.css';

export const Card3 = ({path, name, img, id, amuse_id, location, btnDetail, btnBack, info, type}) => {
  const navigate = useNavigate();
  
  return (
    //rides List
    path !== undefined
    ? <div className="card-wrapper-card3" onClick={e => {
      e.preventDefault();
      window.location.replace(`/${path}/${id}/${amuse_id}`);
    }}>
      <div className="card-body-img">
        <img src={img} alt="img"/>
      </div>
      <div className="card-body-text">
        <div className="card-body-text-title" style={{fontSize:'1.4rem'}}>{name}</div>
      </div>
      <div className="card-footer">
        <div className="card-body-text-content">
          <p>위치: {location}</p>
          {/* <p>{type}</p> */}
        </div>
      </div>
    </div>
    : (
      //fac List
      btnDetail !== undefined 
      ?
      <div className="card-wrapper-card3">
        <div className="card-body-fac-img">
          <img src={img} alt="img"/>
        </div>
        <div className="card-body-fac-text">
          <div className="card-body-text-fac-title">{name}</div>
        </div>
        <div className="card-fac-footer">
          <div className="btn-wrapper-fac">
            <Button type='button' className='btn' onClick={e => {
              e.preventDefault();
              btnDetail(id);
            }}>Detail</Button>
          </div>
        </div>
      </div>
      :
      //fac detail
      <Col className="card-detail-wrapper mb-5">
        <Card className="card-wrapper h-100">
          <img className="card-main-img" src={img} alt="img" />
          <CardBody className="p-4">
            <div className="text-center"><br/>
                <h3 className="fw-bolder">{name}</h3>
            </div>
            <div className="text-center"><br/>
              <h5 style={{fontWeight:'bold'}}>위치: {location}</h5>
              <h5>{info}</h5>
            </div>
          </CardBody>
          <CardFooter className="p-4 pt-0 border-top-0 bg-transparent">
            <div className="btn-wrapper">
              <Button type='button' className="btn" 
                onClick={e => {
                  e.preventDefault();
                  btnBack();
              }}>Back</Button>
            </div>
          </CardFooter>
        </Card>
      </Col>
    )
  );
};