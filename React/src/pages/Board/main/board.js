// import { useEffect, useState } from "react";
// import './board.css'
// import BoardList from "./component/boardList";
// import Tabs from "./component/tabs";
//import 'bootstrap/dist/css/bootstrap.min.css';

// function Board() {




// 	useEffect(() => {
// 		const requestOptions = {
// 			method: "GET",
// 			headers: { "Content-Type": "application.json" },
// 		};


// 	}, []);


// 	const moveWriteForm = () => {
// 		window.location.href = "/addboard";
// 	}

// 	return (
// 		<div>
// 			<section className="notice">
// 				<div id="board-list">
// 					<div className="page-title">
// 						<h1>게시판</h1>
// 					</div>

// 					<div className="container">

// 						<Tabs />

// 						<BoardList />


// 						<div className="page_wrap">
// 							<span className="page_nation"></span>
// 							<span className="write-bottom-wrap" style={{ float: "right" }}>
// 								<button type="submit" id="write-bottom" className="btn btn-blue top" onClick={moveWriteForm} >글쓰기</button>
// 							</span>
// 						</div>

// 					</div>
// 				</div>
// 				<div style={{ clear: "both" }}></div>

// 				<div id="board-search">
// 					<div className="container">
// 						<div className="search-window">
// 							<div className="search-wrap">

// 								<select name="select" id="search_select">
// 									<option value="b_title">제목</option>
// 									<option value="b_content">내용</option>
// 									<option value="member_id">작성자</option>
// 								</select>

// 								<label htmlFor="search" className="blind">공지사항 내용 검색</label>
// 								<input id="text" type="search" name="search" ></input>
// 								<button type="button" className="btn btn-search" >검색</button>
// 							</div>
// 						</div>
// 					</div>
// 				</div>
// 			</section>
// 		</div>
// 	);
// }


// export default Board;