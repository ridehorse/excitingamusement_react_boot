import React, { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { useParams } from 'react-router-dom';
import axios from 'axios';

import 'bootstrap/dist/css/bootstrap.min.css';
import { Container, ListGroup } from 'react-bootstrap';
import './amuseDetail.scss';

import RidesList from '../rides-list/RidesList';
import KakaoMap from '../../components_detail/KakaoMap';
import FacList from '../fac-list/FacList';
import ReviewList from '../review/ReviewList';
import AmuseList from '../amuse-list/AmuseList';
import AmuseListOut from '../amuse-list/AmuseListOut';
import Modal from '../../components_detail/ModalCheck';
import { Cookies } from 'react-cookie';
import ModalChat from '../../components_detail/ModalChat';

const AmuseDetail = (props) => {

    // axios.get('http://localhost:5001/pdData')
    // .then(response => {
    //     console.log("data = ", response.data);
    // })
    // .catch(error => {
    //     console.log(error);
    // })

    const {amuse_id} = useParams();

    const [member_id, setMember_id] = useState();

    useEffect(() => {
        setMember_id(sessionStorage.getItem("MEMBER_ID"));
    },[])

    // const cookies = new Cookies();
    // let viewCookie = null;

    // cookies.set("cookie" + amuse_id, "value", {path: `/amusement/${amuse_id}`});

    // cookies.remove("cookie" + 1, {path:'/amusement/1'});
    // axios.get(`http://localhost:8080/amusement/updateCnt/${amuse_id}`)

    // const COOKIE_KEY = "cookie" + amuse_id;
    // const COOKIE_CHECK = cookies.get("cookie" + amuse_id);
    // let COOKIE_VALUE = sessionStorage.getItem("MEMBER_ID") + "COOKIE" + amuse_id;

    // useLayoutEffect(() => {
    //     //로그인 한 상태
    //     if(sessionStorage.getItem("MEMBER_ID") !== null){
    //         //쿠키 값이 없을 때
    //         if(COOKIE_CHECK.length === 0){
    //             cookies.set(COOKIE_KEY, COOKIE_VALUE, {path:`/amusement/${amuse_id}`});
    //             axios.get(`http://localhost:8080/amusement/updateCnt/${amuse_id}`);
    //         }
    //         // else{ //쿠키 key 값이 이미 존재하는데 value 값은 없을 때
    //         //     if(COOKIE_VALUE !== viewCookie){
    //         //         cookies.set(COOKIE_KEY, COOKIE_VALUE, {path:`/amusement/${amuse_id}`});
    //         //         // axios.get(`http://localhost:8080/amusement/updateCnt/${amuse_id}`);
    //         //     }
    //         // }
    //     }
    // },[]);

    const [amuseDetail, setAmuseDatail] = useState();
    const [amuseImage, setAmuseImage] = useState();

    const [imgUrl, setImgUrl] = useState("");

    useEffect(() => {
        axios.get(`http://localhost:8080/amusement/amuseDetail/${amuse_id}`)
            .then(response => setAmuseDatail(response.data))
    
        axios.get(`http://localhost:8080/amusement/amuseImage/${amuse_id}`)
            .then(response => setAmuseImage(response.data))
    },[amuse_id]);
    
    const handleMouseImage = (url) => {
        setImgUrl(url);
    }

    //반올림 => Math.round

    //scroll 관련
    //브라우저 현재 높이: window.innerHeight
    //document가 수직으로 얼마나 스크롤 됐는지 픽셀 단위로 반환: window.scrollY(window.pageYOffset)

    const [modalOpen, setModalOpen] = useState(false);

    const openModal = () => {
        setModalOpen(true);
    };
    const closeModal = () => {
        setModalOpen(false);
    };

    const [isChk, setIsChk] = useState(false);

    const mouseOver = () => {
        setIsChk(true);
    }
    const mouseLeave = () => {
        setIsChk(false);
    }

    //==============현재 스크롤 위치 파악 & 특정 영역 위치 파악==============
    const [scrollY, setScrollY] = useState(0);

    const facRef = useRef(null);
    const reviewRef = useRef(null);
    const amuseListRef = useRef(null);
    const locaRef = useRef(null);

    const [facY, setFacY] = useState();
    const [reY, setReY] = useState();
    const [amuseY, setAmuseY] = useState();
    const [locaY, setLocaY] = useState();

    useEffect(() => {
      const handleScroll = () => {
        setScrollY(window.scrollY);
      };

      // 스크롤 이벤트 리스너 등록
      window.addEventListener('scroll', handleScroll);
  
      // 컴포넌트 언마운트 시 이벤트 리스너 제거
      return () => {
        window.removeEventListener('scroll', handleScroll);
      };
    }, []);

    useEffect(() => {
        if(!facRef.current || !reviewRef.current || !amuseListRef.current || !locaRef.current) return;
        window.addEventListener("scroll", yScrollEvent);
        return () => {
            window.removeEventListener("scroll", yScrollEvent);
        };
    }, [facRef.current, reviewRef.current, amuseListRef.current, locaRef.current]);

    const yScrollEvent = () => {
        const scroll1 = facRef.current.getBoundingClientRect();
        const scroll2 = reviewRef.current.getBoundingClientRect();
        const scroll3 = amuseListRef.current.getBoundingClientRect();
        const scroll4 = locaRef.current.getBoundingClientRect();

        setFacY(scroll1.y);
        setReY(scroll2.y);
        setAmuseY(scroll3.y);
        setLocaY(scroll4.y);
    }

    return (
        <Container className='d-flex tot-wrapper'>
            <div className='main-wrapper col-md-8'> 
                <Container id='top'>
                    <section className="py-3">
                        <header className='header-title' style={{textAlign:'center', fontWeight:'bold', fontSize: '3rem'}}>{amuseDetail?.a_name}</header><br/>
                        <div style={{fontWeight:'bold', fontSize: '1.3rem', 
                                    backgroundColor:'lightblue', width:'90px', 
                                    textAlign:'center', borderRadius:'10px'}}>{amuseDetail?.a_country}</div>
                        <div style={{fontWeight: 'bold', fontSize: '1.3rem'}}>운영시간: {amuseDetail?.a_time}</div>
                        <a href='#review' style={{textDecoration:'none', color:'black'}}>{(() => {
                            const array = [];
                            for(let i = 0; i < Math.round(amuseDetail?.avg_grade); i++) {
                                array.push(<span key={i}>⭐</span>);
                            }
                            return array;
                        })()}
                        <span style={{fontWeight:'bold'}}>&nbsp;({amuseDetail?.avg_grade}점 / {amuseDetail?.review_cnt}개)</span><br/></a>
                        {/* <span style={{fontWeight:'bold'}}>조회수: {amuseDetail?.a_view}</span> */}
                        <article>
                            <br/>
                            {/* main image */}
                            <div className='main-image-wrapper'>
                                <img src={imgUrl === "" ? amuseDetail?.a_img : imgUrl} 
                                    className='main-image rounded' alt='main'/>
                            </div>
                            <div className='side-image-wrapper d-flex'>
                                {/* side image */}
                                {amuseImage?.map(img => (
                                    <div key={img.aimg_id}>
                                        <img className='side-image rounded' src={img.url} alt='side' 
                                            onMouseMove={e => {
                                                e.preventDefault();
                                                handleMouseImage(img.url);
                                        }}/>
                                    </div>
                                ))}
                            </div>
                        </article>
                        <article className='info-text' id='info'>
                            <br/><br/>
                            {amuseDetail?.a_info}
                        </article>
                    </section>
                </Container>
                <div>
                    <RidesList/>
                </div>
                <div ref={facRef}>
                    <FacList/>
                </div>
                <div ref={reviewRef}>
                    <ReviewList/>
                </div>
                <div ref={amuseListRef}>
                    <br/><br/>
                    <header className='header-title' style={{marginLeft:'10px'}} id='list'>국내외 놀이공원</header>
                    <AmuseList/>
                    <AmuseListOut/>
                </div>
                <div ref={locaRef}>
                    <br/>
                    <KakaoMap lat={amuseDetail?.a_lat} lng={amuseDetail?.a_lng}/>
                </div>
            </div>
            <div className='side-wrapper-cate col-md-4'>
                <Container className="side-box">
                    <section className="py-3">
                        <header className='header-title' 
                            style={{fontSize:'2rem', textAlign:'center'}}>Category</header>
                        <ListGroup style={{textDecoration:'none'}}>
                            <ul className='side-ul'>
                                {/* 0 ~ 953 */}
                                <li style={{backgroundColor: scrollY < 930 ? 'lightblue' : null}}><a href='#top'>Main</a></li>
                                {/* 953 ~ 1353 */}
                                <li style={{backgroundColor: scrollY >= 930 && scrollY < 1270 ? 'lightblue' : null}}><a href='#info'>Info</a></li>
                                {/* ~ 1900 */}
                                <li style={{backgroundColor: scrollY >= 1270 && facY > 20  ? 'lightblue' : null}}><a href='#ride'>Rides</a></li>
                                {/* 1900 ~  */}
                                <li style={{backgroundColor: facY <= 20 && reY > 50 ? 'lightblue' : null}}><a href='#facility'>Facilities</a></li>
                                <li style={{backgroundColor: reY <= 50 && amuseY > 50 ? 'lightblue' : null}}><a href='#review'>Reviews</a></li>
                                <li style={{backgroundColor: amuseY <= 50 && locaY > 200 ? 'lightblue' : null}}><a href='#list'>List</a></li>
                                <li style={{backgroundColor: locaY <= 200 ? 'lightblue' : null}}><a href='#location'>Location</a></li>
                                {/* <li><button onClick={openModal} onMouseOver={mouseOver} onMouseLeave={mouseLeave} 
                                        style={{borderRadius:'10px', border:'1px solid black', height:'40px', backgroundColor: isChk && 'lightblue'}}>
                                    Chat</button></li> */}
                                {/* <li>{scrollY}</li> */}
                            </ul>
                            {/* <React.Fragment>
                                <ModalChat 
                                    open={modalOpen} 
                                    close={closeModal} 
                                    member_id={member_id} 
                                    header="Chat"
                                />
                            </React.Fragment> */}
                        </ListGroup>
                    </section>
                </Container>
            </div>
        </Container>
    );
};

export default AmuseDetail;