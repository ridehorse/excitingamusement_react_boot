import React from 'react';
import './paging.scss';
import Pagination from 'react-js-pagination';

const Paging = ({page, limit, total, setPage}) => {
    return (
        <Pagination
            activePage={page}
            itemsCountPerPage={limit}
            totalItemsCount={total}
            pageRangeDisplayed={5}
            prevPageText={"<"}
            nextPageText={">"}
            onChange={setPage}
        />
    );
};

export default Paging;