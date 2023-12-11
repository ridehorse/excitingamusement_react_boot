import "./App.css";
import React, { useRef } from "react";
import { Route, Routes } from "react-router-dom";
import AddBoard from "./pages/Board/addBoard/addBoard";
import Detail from "./pages/Board/detail/detail";
import UpdateBoard from "./pages/Board/updateBoard/updateBoard";
import ElasticBoard from "./pages/Board/main/ElasticBoard";
import Announcement from "./pages/customerService/announcement/main/announcement";
import AddAnnouncement from "./pages/customerService/announcement/addAnnouncement/addAnnouncement";
import AnnouncementDetail from "./pages/customerService/announcement/detail/announcementDetail";
import UploadAnnouncement from "./pages/customerService/announcement/updateAnnouncement/uploadAnnouncement";
import InsertInquiry from "./pages/customerService/Inquiry/insertInquiry/inserInquiry";
import Inquiry from "./pages/customerService/Inquiry/InquriyList/inquiry";
import InquiryDetail from "./pages/customerService/Inquiry/InquiryDetail/inquiryDetail";
import Layout from "./pages/customerService/components/layout";
import Login from "./login/views/login";
import SignUp from "./login/views/signup";
import SearchPw from "./login/views/searchpw";
import NewPw from "./login/views/newPw";
import PwComplete from "./login/views/pwComplete";
import Menu from "./login/components/Menu";
import { KakaoLogin } from "./login/service/kakaoLogin";
import { KakaoInter } from "./login/views/kakaoInter";
import { FullEditMember } from "./login/views/fullEditMember";
import { FullWriteList } from "./login/views/fullWriteList";
import { GithubLogin } from "./login/views/githubLogin";
import Home from "./screens/Home";
import { List } from "react-bootstrap-icons";
import SelectedMyPage from "./screens/SelectedMyPage";
import HomeModal from "./components/Home/HomeModal";
import FAQ from "./pages/customerService/faq/FAQ";

import Promotion from "./component/Promotion";
import Promotionprice from "./component/Promotionprice";
import Order from "./component/order";
import Mypoint from "./component/mypoint";
import Orderlist from "./component/orderlist";

import Footer from "./components/Footer";

function App() {
  const searchNameRef = useRef();
  const onChangeSearchName = (e) => {
    searchNameRef.current = e.target.value;
    // console.log(searchNameRef.current);
  };
  return (
    <div>
      <Menu
        searchNameRef={searchNameRef}
        onChangeSearchName={onChangeSearchName}
      />
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/signup" element={<SignUp />} />
        <Route path="/writeList/:id" element={<FullWriteList />} />
        <Route path="/searchPw" element={<SearchPw />} />
        <Route path="/newPw" element={<NewPw />} />
        <Route path="/pwComplete" element={<PwComplete />} />
        <Route path="/editMember" element={<FullEditMember />} />
        <Route path="/kakaoLogin" element={<KakaoLogin />} />
        <Route path="/kakaoInter" element={<KakaoInter />} />
        <Route path="/githubLogin" element={<GithubLogin />} />

        <Route path="/promotion" element={<Promotion />} />
        <Route path="/promotionprice" element={<Promotionprice />} />
        <Route path="/order" element={<Order />} />
        <Route path="/mypoint" element={<Mypoint />} />
        <Route path="/orderlist" element={<Orderlist />} />

        <Route path="/" element={<Home />}></Route>
        <Route path="/list" element={<List />}></Route>
        <Route path="/mypage/selectedmypage" element={<SelectedMyPage />}></Route>
        <Route path="/modal" element={<HomeModal />}></Route>

        <Route exact path="board" element={<ElasticBoard />}></Route>
        <Route exact path="addboard" element={<AddBoard></AddBoard>}></Route>
        <Route exact path="detail" element={<Detail />}></Route>
        <Route exact path="updateBoard" element={<UpdateBoard />}></Route>
        <Route element={<Layout />}>
          <Route exact path="announcement" element={<Announcement />}></Route>
          <Route exact path="addAnnouncement" element={<AddAnnouncement />}></Route>
          <Route exact path="announcementDetail" element={<AnnouncementDetail />}></Route>
          <Route exact path="uploadAnnouncement" element={<UploadAnnouncement />}></Route>
          <Route exact path="insertInquiry" element={<InsertInquiry />}></Route>
          <Route exact path="inquiry" element={<Inquiry />}></Route>
          <Route exact path="inquiryDetail" element={<InquiryDetail />}></Route>
          <Route exact path="faq" element={<FAQ></FAQ>}></Route>
        </Route>
      </Routes>
      <Footer />
    </div>
  );
}

export default App;
