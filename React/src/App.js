import { BrowserRouter as Router, Route, Routes } from "react-router-dom";

import AmuseDetail from "./pages/amuse-detail/AmuseDetail";
import RideDetail from "./pages/ride-detail/RideDetail";

import Menu from "./login/components/Menu";

import Home from "./index/screens/Home";
import List from "./index/screens/List";
import SelectedMyPage from "./index/screens/SelectedMyPage";
// import FAQ from './index/screens/FAQ';
import HomeModal from "./index/components/Home/HomeModal";

import { KakaoLogin } from "./login/service/SSOLogin";
import { GithubLogin } from "./login/service/SSOLogin";
import { NaverLogin } from "./login/service/SSOLogin";
import Login from "./login/views/login";
import { useRef } from "react";
// import AmuseList from "./pages/amuse-list/AmuseList";
import Footer from "./index/components/Footer";

import Order from "./component/order";
import Promotion from "./component/Promotion";
import Promotionprice from "./component/Promotionprice";
import Mypoint from "./component/mypoint";
import Orderlist from "./component/orderlist";
import ElasticBoard from "./pages/Board/main/ElasticBoard";
import AddBoard from "./pages/Board/addBoard/addBoard";
import Detail from "./pages/Board/detail/detail";
import UpdateBoard from "./pages/Board/updateBoard/updateBoard";
import Layout from "./pages/customerService/components/layout";
import Announcement from "./pages/customerService/announcement/main/announcement";
import AddAnnouncement from "./pages/customerService/announcement/addAnnouncement/addAnnouncement";
import AnnouncementDetail from "./pages/customerService/announcement/detail/announcementDetail";
import UploadAnnouncement from "./pages/customerService/announcement/updateAnnouncement/uploadAnnouncement";
import InsertInquiry from "./pages/customerService/Inquiry/insertInquiry/inserInquiry";
import Inquiry from "./pages/customerService/Inquiry/InquriyList/inquiry";
import InquiryDetail from "./pages/customerService/Inquiry/InquiryDetail/inquiryDetail";
import FAQ from "./pages/customerService/faq/FAQ";
import SignUp from "./login/views/SignUp";
import NewPw from "./login/views/NewPw";
import PwComplete from "./login/views/PwComplete";
import { FullEditMember } from "./login/views/FullEditMember";
import { KakaoInter } from "./login/views/KaKaoInter";
import { FullWriteList } from "./login/views/FullWriteList";
import SearchPw from "./login/views/Searchpw";
import "bootstrap/dist/css/bootstrap.min.css";
import SignUpComplete from "./login/views/signUpComplete";

const App = () => {
  const searchNameRef = useRef();
  const onChangeSearchName = (e) => {
    searchNameRef.current = e.target.value;
    // console.log(searchNameRef.current);
  };

  return (
    <Router>
      {/* <Menu/> */}
      <Menu
        searchNameRef={searchNameRef}
        onChangeSearchName={onChangeSearchName}
      />
      <Routes>
        {/* 일준 */}
        {/* <Route path="/board" element={<ReviewListPaging/>}/> */}
        {/* <Route path="/" element={<AmuseList/>}/> */}
        <Route path="/amusement/:amuse_id" element={<AmuseDetail />} />
        <Route
          path="/rideDetail/:rides_id/:amuse_id"
          element={<RideDetail />}
        />

        {/* 시진형 */}
        <Route path="/login" element={<Login />} />
        <Route path="/signup" element={<SignUp />} />
        <Route path="/newPw" element={<NewPw />} />
        <Route path="/pwComplete" element={<PwComplete />} />
        <Route path="/editMember" element={<FullEditMember />} />
        {/* <Route path="/kakaoLogin" element={<KakaoLogin />} /> */}
        <Route path="/kakaoInter" element={<KakaoInter />} />
        <Route path="/githubLogin" element={<GithubLogin />} />
        <Route path="/kakaoLogin" element={<KakaoLogin />} />
        <Route path="/naverLogin" element={<NaverLogin />} />
        <Route path="/writeList/:id" element={<FullWriteList />} />
        <Route path="/searchPw" element={<SearchPw />} />
        <Route path="/signupComplete" element={<SignUpComplete />} />

        {/* 효원*/}
        <Route path="/promotion" element={<Promotion />} />
        <Route path="/promotionprice" element={<Promotionprice />} />
        <Route path="/order" element={<Order />} />
        <Route path="/mypoint" element={<Mypoint />} />
        <Route path="/orderlist" element={<Orderlist />} />

        {/* 동욱 */}
        <Route path="/" element={<Home />}></Route>
        <Route path="/list" element={<List />}></Route>
        <Route
          path="/mypage/selectedmypage"
          element={<SelectedMyPage />}
        ></Route>
        {/* <Route path = "/customer/faq" element= { <FAQ />}></Route> */}
        <Route path="/modal" element={<HomeModal />}></Route>

        {/* 덕용 */}
        <Route exact path="board" element={<ElasticBoard />}></Route>
        <Route exact path="addboard" element={<AddBoard></AddBoard>}></Route>
        <Route exact path="detail" element={<Detail />}></Route>
        <Route exact path="updateBoard" element={<UpdateBoard />}></Route>
        <Route element={<Layout />}>
          <Route exact path="announcement" element={<Announcement />}></Route>
          <Route
            exact
            path="addAnnouncement"
            element={<AddAnnouncement />}
          ></Route>
          <Route
            exact
            path="announcementDetail"
            element={<AnnouncementDetail />}
          ></Route>
          <Route
            exact
            path="uploadAnnouncement"
            element={<UploadAnnouncement />}
          ></Route>
          <Route exact path="insertInquiry" element={<InsertInquiry />}></Route>
          <Route exact path="inquiry" element={<Inquiry />}></Route>
          <Route exact path="inquiryDetail" element={<InquiryDetail />}></Route>
          <Route exact path="faq" element={<FAQ />}></Route>
        </Route>
      </Routes>
      {/* <Footer /> */}
    </Router>
  );
};

export default App;
