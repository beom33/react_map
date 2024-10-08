import React, { useState } from 'react';
import { Helmet } from 'react-helmet-async';
import { useTranslation } from 'react-i18next';
import KakaoMap from '../../../map/KakaoMap';
import {
  OuterBox,
  PageNav,
  PageNavWrap,
  PageTitle,
  ContentBox,
} from '../../../commons/components/LayoutBox';
import ViewContainer from '../containers/ViewContainer';

const options = {
  currentLocation: true,
  zoom: 3,
};

const MylocationView = () => {
  const [SubPageTitle, setSubPageTitle] = useState('');
  const { t } = useTranslation();
  return (
    <>
      <Helmet>
        <title>{SubPageTitle}</title>
      </Helmet>
      <OuterBox>
        <PageNavWrap>
          <PageNav>
            <h3>이동 / 이동 / 이동</h3>
          </PageNav>
          <PageTitle>
            <h1>내 위치 주변 농촌 체험</h1>
          </PageTitle>
        </PageNavWrap>
        <ContentBox>
          <h1>{SubPageTitle}</h1>
          <KakaoMap {...options} />;
        </ContentBox>
      </OuterBox>
    </>
  );
};

export default React.memo(MylocationView);
