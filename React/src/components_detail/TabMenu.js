import React, { useEffect, useState } from 'react';

import { Container, ListGroup } from 'react-bootstrap';
import { useParams } from 'react-router-dom';
import axios from 'axios';

import 'slick-carousel/slick/slick.css';
import 'slick-carousel/slick/slick-theme.css';
import 'bootstrap/dist/css/bootstrap.min.css';
import Slider from 'react-slick';
import { Card } from './Card';

import './tabMenu.scss';
import { Card3 } from './Card3';

const TabMenu = () => {

    const [selectedTab, setSelectedTab] = useState(0);
    
    const { rides_id, amuse_id } = useParams();

    const [rideDetail, setRideDetail] = useState();
    const [ridesList, setRidesList] = useState();

    const [inAvgGradeList, setInAvgGradeList] = useState([]);

    //console.log("amuse_id", amuse_id);

    const settings = {
        infinite : true,      // 무한 반복 옵션     
        slidesToShow : 3,     // 한 화면에 보여질 컨텐츠 개수
        slidesToScroll : 1,   // 스크롤 한번에 움직일 컨텐츠 개수
        speed : 1000,         // 다음 버튼 누르고 다음 화면 뜨는데까지 걸리는 시간(ms)
        dots : true,          // 스크롤바 아래 점으로 페이지네이션 여부
        autoplay : true,      // 자동 스크롤 사용 여부
        draggable : false       //드래그 가능 여부
      }
    
    useEffect(() => {
        axios.get(`http://localhost:8080/amusement/rideDetail/${rides_id}`)
            .then(response => setRideDetail(response.data));
        axios.get(`http://localhost:8080/amusement/ridesList/${amuse_id}`)
            .then(response => setRidesList(response.data));
        axios.get(`http://localhost:8080/amusement/inAvgGradeList`)
        .then(response => setInAvgGradeList(response.data));
    },[rides_id, amuse_id]);

    const menuArr = [
        {   name: '탑승영상', 
            content: 
                <iframe 
                    id="inlineFrameExample"
                    title="Inline Frame Example"
                    width="100%"
                    height="450px"
                    autoPlay
                    style={{borderRadius:'20px'}}
                    src={rideDetail?.r_video}>
                </iframe>
        },
        {   name: '정보', 
            content: 
                <ListGroup style={{listStyle:'none', width:'100%', height:'auto',
                                margin:'auto', backgroundColor:'whitesmoke', borderRadius:'10px', padding:'20px'}}>
                    <li style={{marginBottom:'20px', textAlign:'left', fontSize:'1.7rem', fontWeight:'bold'}}>
                        {rideDetail?.r_info}
                    </li>
                    <li style={{textAlign:'left', padding:'10px', fontSize:'1.3rem'}}>
                        <span style={{fontWeight:'bold'}}>위치:</span>&nbsp;&nbsp;{rideDetail?.r_location}
                    </li>
                    <li style={{textAlign:'left', padding:'10px', fontSize:'1.3rem'}}>
                        <span style={{fontWeight:'bold'}}>신장 조건:</span>&nbsp;&nbsp;
                        {rideDetail?.r_min_height} 이상 {rideDetail?.r_max_height} 이하 
                    </li>
                </ListGroup>
        },
        {   name: '추천 놀이기구', 
            content:
            <Container>
                <Slider {...settings}>
                    {ridesList?.map(rList => (
                        <Card3 key={rList.rides_id} id={rList.rides_id} path="rideDetail" amuse_id={amuse_id}
                        name={rList.r_name} img={rList.r_img} location={rList.r_location} type={rList.r_type}/>
                    ))}
                </Slider>
            </Container>
        },
        {   name: '추천 놀이공원', 
            content:
            <Container>
                <Slider {...settings}>
                    {inAvgGradeList.map(amuse => (
                        <Card key={amuse.amuse_id} id={amuse.amuse_id} path="amusement"
                        name={amuse.a_name} country={amuse.a_country} img={amuse.a_img}
                        avg={amuse.avg_grade} review_cnt={amuse.review_cnt}/>
                    ))}
            </Slider>
            </Container>
        }
    ];

    const selectMenuHandler = (index) => {
        // console.log("index", index);
        setSelectedTab(index);
    }

    return (
        <Container>
            <div className="tab-menu">
                {menuArr?.map((tab, index) =>  (
                    <li key={index} className={index === selectedTab ? "sub-menu focused" : "sub-menu"}
                        onClick={() => selectMenuHandler(index)}>
                    <p style={{margin:'auto'}}>{tab.name}</p>
                    </li>
                ))}
            </div>
            <div className='tab-content'>
                <br/>
                {menuArr[selectedTab].content}
            </div>
        </Container>
    );
};

export default TabMenu;