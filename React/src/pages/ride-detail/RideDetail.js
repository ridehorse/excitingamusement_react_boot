import axios from 'axios';
import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { Container, List } from 'reactstrap';
import './rideDetail2.scss';
import TabMenu from '../../components_detail/TabMenu';
import Loading from '../../components_detail/Loading';

const RideDetail = () => {
    const { rides_id } = useParams();
    const [rideDetail, setRideDetail] = useState();

    useEffect(() => {
        axios.get(`http://localhost:8080/amusement/rideDetail/${rides_id}`)
            .then(response => setRideDetail(response.data))
    },[rides_id]);
    
    //console.log(rideDetail?.r_video);

    const [loading, setLoading] = useState(true);
    useEffect(() => {
        //2초 후에 alert의 상태 값을 true => false로 변경
        let timer = setTimeout(() => {setLoading(false)}, 1000);
    },[])

    return (
    // <div className='fluid' style={{height:'1500px'}}>
    //     {loading ? <Loading/> : null}
    //     <div className='ride-detail-wrapper'>
    //         <img src={rideDetail?.r_img} className='ride-tot-img col-md-7' alt='totImg'/>
    //         <List type='unstyled' className='ride-list-wrapper'>
    //             <li>
    //                 <img src={rideDetail?.r_img} className='ride-main-img' alt='mainImg'/>   
    //             </li>
    //             <div className='ride-second-wrapper'>
    //                 <div style={{fontSize:'2.5rem', color:'black', fontWeight:'bold'}}>
    //                     {rideDetail?.r_name}
    //                 </div>
                    
    //             </div>
    //         </List>
    //     </div>
    //     <Container>
    //         <br/>
    //         <TabMenu/>
    //     </Container>
    // </div>

    <div className='fluid'>
        {loading ? <Loading/> : null}
        <div className='ride-detail-wrapper' 
            style={{backgroundImage:`url(${rideDetail && rideDetail.r_img})`}}>
        <div style={{
            position:'sticky', 
            top:'20%',
            margin:'auto',
            borderRadius:'20px',
            backgroundColor:'whitesmoke',
            width:'550px'
            }}>
        <h2 style={{
            fontSize:'3rem', 
            fontWeight:'bold'
            }}>
        {rideDetail && rideDetail.r_name}</h2></div>
        </div>
        <div style={{position: 'sticky', top:'900px'}}><TabMenu/></div>
    </div>
    );
};

export default RideDetail;