import axios from 'axios';
import React, { useEffect, useState } from 'react';
import 'bootstrap/dist/css/bootstrap.min.css';
import { Container } from 'react-bootstrap';
import Paging from '../../components_detail/Paging';

const ReviewListPaging = () => {

    const [posts, setPosts] = useState([]);

    //페이지 별 게시물 개수(한 페이지에 보여지는 게시물 개수)
    const [limit, setLimit] = useState(5);

    //현재 페이지 번호
    const [page, setPage] = useState(1);

    //const [selectedOption, setSelectedOption] = useState();

    const offset = (page - 1) * limit;

    useEffect(() => {
        axios.get(`http://localhost:8080/test/reviewList/1`)
            .then(response => setPosts(response.data))
    },[]);

    const handleChangeSelect = e => {
        setLimit(e.target.value);
    }

    const totalPageCnt = posts.length;
    
    return (
        <Container>
            <header><h3>Board</h3></header>
            
            <main>
                {posts.slice(offset, offset + limit).map(post => (
                    <div key={post.review_id}>
                        <h4>{post.review_id}</h4>
                        <h4>{post.r_regidate}</h4>
                    </div>
                ))}
            </main>
            <Paging limit={limit} total={totalPageCnt} setPage={setPage}/>
        </Container>
    );
};

export default ReviewListPaging;