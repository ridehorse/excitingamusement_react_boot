import React, { useState, useEffect} from 'react';
import InfiniteScroll from 'react-infinite-scroll-component';
import axios from 'axios';
import { Col, Container, Form, FormControl, InputGroup, Row } from 'react-bootstrap';
import ListItem from '../components/List/ListItem';
import ToastNotification from '../components/ToastNotification';
import MapTest from '../components/List/MapTest';

const List = () => {
  const [items, setItems] = useState([]);
  const [hasMore, setHasMore] = useState(true);
  sessionStorage.setItem('member_id','hong1');
  const member_id = sessionStorage.getItem('member_id'); 
  const [toast, setToast] = useState({ show: false, message: "", type : "" });
  const [searchName, setSearchName] = useState();
  const [searchCountry, setSearchCountry] = useState('');
  const [pageNum, setPageNum] = useState(1);
  const [order, setOrder] = useState('신설순');
  
  // 검색 조건이 변경될 때 실행되는 useEffect
  useEffect(() => {
    setPageNum(1);
    fetchData(searchName, searchCountry, 1, order); // pageNum 대신 1을 전달합니다.
    // console.log('조건스크롤');
  }, [searchName, searchCountry, order]);

  // 무한 스크롤 처리를 위한 useEffect
  useEffect(() => {
    fetchData(searchName, searchCountry, pageNum, order);
    // console.log('무한스크롤');
  }, [pageNum]);

  const url = 'http://localhost:8080/list';
  
  const fetchData = async (searchName, searchCountry, pageNum, order) => {
    try {
      console.log(searchName);
      console.log(searchCountry);
      console.log(pageNum);
      console.log(order);
      const response = await axios.get(url, {
        params: {
          searchName: searchName,
          searchCountry: searchCountry,
          pageNum: pageNum,
          order: order,
        },
      });
      // setPageNum(pageNum+1);
      const newItems = response.data.listData; // 새롭게 가져온 아이템들
      console.log(newItems);
      if (newItems.length === 0) {
        setHasMore(false);
      } else {
        setHasMore(true);
      }
      if (pageNum === 1) {
        setItems(newItems); // 검색 조건이 변경된 경우, 전체 데이터를 대체합니다.
      } else {
        setItems([...items, ...newItems]); // 페이지의 이전 데이터와 새로운 데이터를 병합합니다.
      }
      console.log(newItems);
    } catch (error) {
      console.log(error);
    }
  };

  const onChangeListData = (e) => {
    setSearchName(e.target.value);
  };

  const handleShowToast = (message, type) => {
    setToast({ show: true, message, type });
    setTimeout(() => {
      setToast({ show: false, message: '', type });
    }, 1200);
  };
  
  return (
    <div>
      <div>
      <Container className="my-5 border-bottom">
        {items && (
          <Row className="mb-3" style={{ height: '300px' }}>
            {/* <MyMapComponent markers={data.listData}/> */}
            <MapTest markers={items}/>
          </Row>
        )}
        <Row>
          <Col>
            <Form.Group controlId="floatingInput" className="mb-3">
              <InputGroup>
                <FormControl type="search" name="searchName" placeholder="놀이공원을 찾아볼까요?" onChange={onChangeListData} />
              </InputGroup>
            </Form.Group>
          </Col>
        </Row>
         <div className="row">
      <div className="d-flex">
        <div className="btn-group me-auto" role="group" aria-label="Basic radio toggle button group">
          {[
            { id: 'country-radio1', value: '', label: '전체' },
            { id: 'country-radio2', value: '대한민국', label: '국내' },
            { id: 'country-radio3', value: '일본', label: '일본' },
            { id: 'country-radio4', value: '미국', label: '미국' },
            { id: 'country-radio5', value: '중국', label: '중국' },
          ].map((item) => (
            <React.Fragment key={item.id}>
              <input
                type="radio"
                className="btn-check"
                name="searchCountry"
                id={item.id}
                value={item.value}
                autoComplete="off"
                checked={searchCountry === item.value}
                onChange={() => setSearchCountry(item.value)}
              />
              <label className="btn btn-outline-primary index-radio px-4" htmlFor={item.id}>
                {item.label}
              </label>
            </React.Fragment>
          ))}
        </div>
        <div className="btn-group" role="group" aria-label="Basic radio toggle button group">
          {[
            { id: 'order-radio1', value: '신설순', label: '신설순' },
            { id: 'order-radio2', value: '조회순', label: '조회순' },
          ].map((item) => (
            <React.Fragment key={item.id}>
              <input
                type="radio"
                className="btn-check"
                name="order"
                id={item.id}
                value={item.value}
                autoComplete="off"
                checked={order === item.value}
                onChange={() => setOrder(item.value)}
              />
              <label className="btn btn-outline-secondary index-radio" htmlFor={item.id}>
                {item.label}
              </label>
            </React.Fragment>
          ))}
        </div>
      </div>
    </div>
      <InfiniteScroll
        dataLength={items.length} // 현재까지 렌더링된 아이템 수
        next={async () => {
          setPageNum(pageNum + 1);
          await fetchData(searchName, searchCountry, pageNum + 1, order); // 기존 코드에서 pageNum을 1 증가 시킨 값을 인자로 전달합니다.
        }} // 추가 데이터를 가져오는 함수        
        hasMore={hasMore} // 더 가져올 데이터가 있는지 여부(true/false)
        loader={<h4>loading......</h4>} // 로딩 표시 컴포넌트
        endMessage={
            <b>모든 데이터를 불러왔습니다.</b>
        }
      >
        <Row className="gx-4 gx-lg-5 row-cols-2 row-cols-md-3 row-cols-xl-4 py-4">
          {items && items.map((item) => (
            <ListItem key={item.amuse_id} item={item} member_id={member_id} handleShowToast={handleShowToast}/>
          ))}
        </Row>
      </InfiniteScroll>
    </ Container>
    </div>
      <ToastNotification toast={toast} />
    </div>
  );
};

export default List;
