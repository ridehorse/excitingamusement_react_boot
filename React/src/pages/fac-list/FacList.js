import React from 'react';
import { useEffect, useState } from 'react';
import axios from 'axios';
import { useParams } from 'react-router-dom';
import 'bootstrap/dist/css/bootstrap.min.css';
import { Button, Container } from 'reactstrap';
import { Card3 } from '../../components_detail/Card3';

const FacList = () => {
    const { amuse_id } = useParams();
    const [facList, setFacList] = useState();
    const [facId, setFacId] = useState(null);

    useEffect(() => {
        axios.get(`http://localhost:8080/amusement/facilityList/${amuse_id}`)
            .then(response => setFacList(response.data));
    },[facId]);
    
    const facDetail = id => {
        setFacId(id);
    }

    //Back 버튼 클릭
    const facBack = () => {
        setFacId(null);
        return (
        <Container className="mt-5">
            <section className="py-5">
                <header className='header-title'>편의시설</header>
                    <div className="row gx-4 gx-lg-5 row-cols-2 row-cols-md-3 
                                row-cols-xl-4 justify-content-center">
                    {facList?.map(fac => {
                        if(facId === fac.facility_id){
                            return(
                                <Card3 key={fac.facility_id} info={fac.f_info} location={fac.f_location}
                                    name={fac.f_name} img={fac.f_img} btnHandle={facBack}/>
                            );
                        }
                    })}
                    </div>
            </section>
        </Container>
        )
    }

    //paging
    let content = null;
    const [limit, setLimit] = useState(3);

    if(limit < facList?.length){
        content = <Button className='more-btn' style={{marginTop:'5%', 
                                marginLeft:'38%', 
                                width:'200px'}} 
            onClick={() => {
                setLimit(limit + 3);
            }}>더보기</Button>
    }
    else{
        content = <Button style={{marginTop:'5%', marginLeft:'38%', width:'200px'}} 
            onClick={() => {
                setLimit(3);
        }}>접기</Button>
    }
    
    //return 분기
    if(facId === null){
        return (
        <Container id='facility' className="fac-wrapper mt-5">
            <section className="py-5">
                <header className='header-title'>편의시설</header>
                <div className="row gx-4 gx-lg-5 row-cols-2 row-cols-md-3 
                            row-cols-xl-4 justify-content-center">
                {facList?.slice(0, limit).map(fac => (
                    <Card3 key={fac.facility_id} id={fac.facility_id} 
                        name={fac.f_name} img={fac.f_img} btnDetail={facDetail}/>
                ))}
                </div>
                {content}
            </section>
        </Container>
        );
    }
    else{
        return (
        <Container id='facility' className="mt-5">
            <section className="py-5">
                <header className='header-title'>편의시설</header>
                    <div className="row gx-4 gx-lg-5 row-cols-2 row-cols-md-3 
                                row-cols-xl-4 justify-content-center">
                    {facList?.map(fac => {
                        if(facId === fac.facility_id){
                            return(
                                <Card3 key={fac.facility_id} info={fac.f_info} location={fac.f_location}
                                    name={fac.f_name} img={fac.f_img} btnBack={facBack}/>
                            );
                        }
                    })}
                    </div>
            </section>
        </Container>
        );
    }
};

export default FacList;
