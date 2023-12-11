import axios from 'axios';
import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';

import 'bootstrap/dist/css/bootstrap.min.css';
import './reviewList.scss';
import { Button, Container, Table } from 'reactstrap';
import StarRating from '../../components_detail/StarRating';
import Paging from '../../components_detail/Paging';
import Modal from '../../components_detail/ModalCheck';

//글 작성
function Write(props){
    const [memberId, setMemberId] = useState("");
    const [content, setContent] = useState("");
    const [ratingNum, setRatingNum] = useState(null);

    const [idChk, setIdChk] = useState(false);

    const starRatingFunc = rating => {
        setRatingNum(rating);
    }

    const [modalOpen, setModalOpen] = useState(false);

    const openModal = () => {
        setModalOpen(true);
    };
    const closeModal = () => {
        setModalOpen(false);
    };
    const checkModal = () => {
        setModalOpen(false);
    }
    
    // useEffect(()=>{
    //     console.log("ratingNum", ratingNum);
    // },[ratingNum])

    return <Container className="px-4 px-lg-5 mt-5">
        <form onSubmit={e => {
        e.preventDefault();
        // const memberId = e.target.memberId.value;
        const content = e.target.content.value;
        const amuse_id = Number(props.amuse_id);
        const member_id = sessionStorage.getItem("MEMBER_ID");

        // post로 서버에 데이터 전달
        // 등록
        
        if(sessionStorage.getItem("MEMBER_ID") === null){
            setIdChk(false);
            openModal();
        }
        else if(content.length === 0 || ratingNum === null){
            setIdChk(true);
            openModal();
        }
        else{
            axios.post("http://localhost:8080/amusement/write", {
                amuse_id: amuse_id,
                member_id: member_id,
                r_content: content,
                r_grade: ratingNum
            },[])
            .then(result => props.onWrite());
        }
        
    }}>
        {/* star rating component */}
        <StarRating starRatingFunc={starRatingFunc}/>
        <br/>
        <input 
            type="hidden"
            name="memberId"
            value={memberId}
            onChange={e => {
                setMemberId(e.target.value);
            }}/>
        <textarea 
            type="text"
            name="content"
            value={content}
            placeholder='후기 작성'
            style={{margin:'auto', width:'100%', height:'4.5rem'}}
            onChange={e => {
                setContent(e.target.value);
            }}/>
        <div style={{float:'right'}}>
            <input type='submit' className='btn btn-outline-dark mt-auto' value="Write"/>&nbsp;
            <input type='button' className='btn btn-outline-dark mt-auto' value="Close" onClick={e => {
                props.setMode("");
            }}/>
        </div>
    </form>
    <React.Fragment>
        <Modal open={modalOpen} close={closeModal} check={checkModal} header="Warning!">
        <main style={{fontSize:'1.5rem'}}>
            {idChk === true ? "점수 혹은 후기를 작성해주세요" : "로그인 후 작성 가능합니다"}
        </main>
        </Modal>
    </React.Fragment>
    </Container>
}

//답글 처리
function Answer(props){
    const [content, setContent] = useState("");

    const [modalOpen, setModalOpen] = useState(false);

    const openModal = () => {
        setModalOpen(true);
    };
    const closeModal = () => {
        setModalOpen(false);
    };
    const checkModal = () => {
        setModalOpen(false);
    };

    return <form 
        onSubmit={e => {
        e.preventDefault();
        const memberId = "hong1";
        const content = e.target.content.value;
        const amuse_id = Number(props.amuse_id);
        const review_id = Number(props.review_id);
        
        if(content.length !== 0){
            axios.post("http://localhost:8080/amusement/answer", {
                amuse_id: amuse_id,
                member_id: memberId,
                r_content: " ㄴ " + content,
                review_id: review_id
            },[]).then(result => props.onAnswer());
        }
        else{
            openModal();
            //alert("답글을 입력해주세요");
        }
    }}>
        <br/>
        <textarea 
            type="text"
            name="content"
            value={content}
            placeholder='답글 작성'
            style={{margin:'auto', width:'100%', height:'4.5rem'}}
            onChange={e => {
                setContent(e.target.value);
            }}/>
        <div style={{float:'right'}}>
            <input type='submit' className='btn btn-outline-dark mt-auto' value="Answer"/>&nbsp;
            <input type='button' className='btn btn-outline-dark mt-auto' value="Close" onClick={e => {
                props.setMode("");
                props.setSelectedReviewId(null);
            }}/>
        </div>
        <React.Fragment>
            <Modal open={modalOpen} close={closeModal} check={checkModal} header="Warning!">
                <main>답글을 작성해주세요</main>
            </Modal>
        </React.Fragment>
    </form>
}

const ReviewList = () => {
    // const member_id = sessionStorage.getItem("MEMBER_ID");

    const {amuse_id} = useParams();
    
    //paging에서 post
    const [review, setReview] = useState([]);
    const [mode, setMode] = useState("");
    const [review_id, setReview_id] = useState();

    const [selectedReviewId, setSelectedReviewId] = useState(null);

    const [modalOpen, setModalOpen] = useState(false);

    const openModal = () => {
        setModalOpen(true);
    };
    const closeModal = () => {
        setModalOpen(false);
    };
    const checkModal = () => {
        setModalOpen(false);
        axios.get(`http://localhost:8080/amusement/delete/${review_id}`)
                .then(() => setMode(""));
    };

    //=================paging=================
    //페이지 별 게시물 개수(한 페이지에 보여지는 게시물 개수)
    const [limit, setLimit] = useState(5);
    //현재 페이지 번호
    const [page, setPage] = useState(1);
    //페이지 별 첫 게시물의 index 값
    const offset = (page - 1) * limit;
    //전체 게시글 개수
    const totalPageCnt = review.length;

    //글, 답글 작성 및 삭제할 때에도 다시 렌더링 되도록 하는 방법???
    useEffect(() => {
        axios.get(`http://localhost:8080/amusement/reviewList/${amuse_id}`)
            .then(response => setReview(response.data))
    },[mode, review_id, amuse_id, review.length]);

    // console.log("isChk", isChk);

    let content, write = null;

    if(mode === ""){
        write = <button className="btn btn-outline-dark mt-auto"
            style={{float:'right', fontWeight:'bold'}}    
            onClick={e => {
                e.preventDefault();
                setMode("WRITE");
            }}>Write
        </button>
    }
    else if(mode === "WRITE"){
        content = 
        <Write setMode={setMode} amuse_id={amuse_id} onWrite={() => {
            setMode("");
            setPage(1);
        }}></Write>
    }
    else if(mode === "ANSWER"){
        content = 
        <Answer setMode={setMode} setSelectedReviewId={setSelectedReviewId} 
                amuse_id={amuse_id} review_id={review_id} 
                    onAnswer={() => {
                        setMode("");
                        setSelectedReviewId(null);
                    }}>
        </Answer>
    }

    const handleAnswerClick = review_id => {
        //console.log("button으로 받아온 review_id = ", review_id);
        setReview_id(review_id);
        setSelectedReviewId(review_id);
        setMode("ANSWER");
    }

    const handleChangeSelect = e => {
        setLimit(Number(e.target.value));
        setPage(1);
    }

    const reviewDelete = (review_id) => {
        openModal();
        setMode("DELETE");
        setReview_id(review_id);
    }

    return (
        <Container id='review' className="mt-5">
            <header className='header-title' id='ride'>후기</header>
            <label style={{float:'right'}}>
                <select
                    type="number"
                    style={{height:'30px'}}
                    onChange={handleChangeSelect}
                >
                    <option value="5">5개씩 보기</option>
                    <option value="10">10개씩 보기</option>
                    <option value="20">20개씩 보기</option>
                    <option value="30">30개씩 보기</option>
                </select>
            </label>
            <Table className='table-borderless text-center' style={{borderRadius:'20px'}}>
                <thead className='border-bottom'>
                    <tr>
                        <th>No</th>
                        <th>Id</th>
                        <th>Content</th>
                        <th>Regidate</th>
                        <th></th>
                    </tr>
                </thead>
                <tbody>
                {review?.slice(offset, offset + limit).map((review, index) => (
                    <tr key={review.review_id} className='text-center'>
                        <td>{index + 1}</td>
                        {/* <td>{review.member_id.replace(/\d{3}$/, '***')}</td> */}
                        <td>{review.member_id.replace(review.member_id.slice(-2), "**")}</td>
                        <td>{review.r_content}</td>
                        <td>{review.r_regidate}</td>    
                        <td>
                        {
                        sessionStorage.getItem("MEMBER_ID") === review.member_id &&
                        <Button type='button' className='mt-auto'
                            onClick={e => {
                                // e.preventDefault();
                                reviewDelete(review.review_id);
                        }}>Delete</Button>
                        }
                        &nbsp;
                        {
                        sessionStorage.getItem("MEMBER_ID") === "admin" &&
                        <Button type='button' className='mt-auto'
                            style={{backgroundColor: selectedReviewId === review.review_id && 'lightseagreen'}}
                            onClick={e => {
                                e.preventDefault();
                                handleAnswerClick(review.review_id);
                                //첫번째 버튼과 두번째 버튼 비교
                                //왜 첫번째 버튼에서는 이렇게 하면 review_id 받을 수 있고
                                //왜 두번째 버튼에서는 이렇게 하면 못 받는지!!
                                //alert(review.review_id);
                                //setMode("ANSWER");
                        }}>Answer</Button>
                        }
                        </td>
                    </tr>
                ))}
                </tbody>
            </Table>
            <Paging limit={limit} total={totalPageCnt} page={page} setPage={setPage}/>
            {write}
            {content}

            <React.Fragment>
                <Modal open={modalOpen} close={closeModal} check={checkModal} header="Confirm!">
                    <main>삭제할까요?</main>
                </Modal>
            </React.Fragment>
            
        </Container>
    );
};

export default ReviewList;