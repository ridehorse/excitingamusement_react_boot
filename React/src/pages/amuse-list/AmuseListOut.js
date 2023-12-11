import axios from 'axios';
import React, { useEffect, useState } from 'react';
import {Card} from "../../components_detail/Card";

import 'slick-carousel/slick/slick.css';
import 'slick-carousel/slick/slick-theme.css';
import Slider from 'react-slick';
import { Container } from 'react-bootstrap';

const AmuseListOut = () => {
    const [opt, setOpt] = useState("");

    const [outAvgGradeList, setOutAvgGradeList] = useState([]);
    const [outReviewCntList, setOutReviewCntList] = useState([]);

    useEffect(() => {
    axios.get('http://localhost:8080/amusement/outAvgGradeList')
      .then(response => setOutAvgGradeList(response.data))

    axios.get('http://localhost:8080/amusement/outReviewCntList')
      .then(response => setOutReviewCntList(response.data))
    },[]);

    const settings = {
      infinite : true,      // 무한 반복 옵션     
      slidesToShow : 3,     // 한 화면에 보여질 컨텐츠 개수
      slidesToScroll : 1,   // 스크롤 한번에 움직일 컨텐츠 개수
      speed : 1500,         // 다음 버튼 누르고 다음 화면 뜨는데까지 걸리는 시간(ms)
      dots : false,          // 스크롤바 아래 점으로 페이지네이션 여부
      autoplay : true,      // 자동 스크롤 사용 여부
      autoplaySpeed : 2000, // 자동 스크롤 시 다음으로 넘어가는데 걸리는 시간 (ms)
      pauseOnHover : true,  // 슬라이드 이동 시 마우스 호버하면 슬라이더 멈추게 설정
      draggable : false     //드래그 가능 여부
    }

    let amuse_list = 
        <Slider {...settings}>
            {outAvgGradeList.map(amuse => (
                <Card key={amuse.amuse_id} id={amuse.amuse_id} path="amusement"
                name={amuse.a_name} country={amuse.a_country} img={amuse.a_img}
                avg={amuse.avg_grade} review_cnt={amuse.review_cnt}/>
            ))}
        </Slider>

    if(opt === "avg"){
        amuse_list = 
            <Slider {...settings}>
                {outAvgGradeList.map(amuse => (
                    <Card key={amuse.amuse_id} id={amuse.amuse_id} path="amusement"
                    name={amuse.a_name} country={amuse.a_country} img={amuse.a_img}
                    avg={amuse.avg_grade} review_cnt={amuse.review_cnt}/>
                ))}
            </Slider>
    }
    else if(opt === "review"){
        amuse_list = 
            <Slider {...settings}>
                {outReviewCntList.map(amuse => (
                    <Card key={amuse.amuse_id} id={amuse.amuse_id} path="amusement"
                    name={amuse.a_name} country={amuse.a_country} img={amuse.a_img}
                    avg={amuse.avg_grade} review_cnt={amuse.review_cnt}/>
                ))}
            </Slider>
    }

    const handleChangeSelect = e => {
        setOpt(e.target.value);
    }

    return (
        <Container className='amuseList-wrapper mt-5'>
            <div className='amuseList-body' style={{position:'relative', left:'84%'}}>
                <select onChange={handleChangeSelect} style={{height:'30px'}}>
                    <option value="avg">평점 높은 순서</option>
                    <option value="review">후기 많은 순서</option>
                </select>
            </div>
            {amuse_list}
        </Container>
    );
};

export default AmuseListOut;